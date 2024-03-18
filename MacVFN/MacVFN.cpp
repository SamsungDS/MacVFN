//
//  MacVFN.cpp
//  MacVFN
//
//  Created by Mads Ynddal on 24/11/2023.
//

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOLib.h>
#include <DriverKit/DriverKit.h>
#include <DriverKit/IOMemoryDescriptor.h>
#include <DriverKit/IODMACommand.h>
#include <DriverKit/OSDictionary.h>
#include <PCIDriverKit/PCIDriverKit.h>
#include <DriverKit/IOInterruptDispatchSource.h>

#include "MacVFN.h"
#include "MacVFNUserClient.h"
#include "MacVFNShared.h"

#include <vfn/nvme.h>
#include "libvfn/src/iommu/context.h"

#define MAX_QUEUE_COUNT 16

struct MemoryDescriptorPair{
    void *vaddr;
    IOBufferMemoryDescriptor *vaddr_descriptor;
};

struct MacVFN_IVars
{
    IOPCIDevice* pciDevice;

    struct MemoryDescriptorPair sq_buffer_descriptors[MAX_QUEUE_COUNT];
    struct MemoryDescriptorPair cq_buffer_descriptors[MAX_QUEUE_COUNT];
    RingQueue* cq_ring_queues[MAX_QUEUE_COUNT];
    RingQueue* sq_ring_queues[MAX_QUEUE_COUNT];

    int user_clients;

    struct nvme_ctrl ctrl;
};

bool MacVFN::init(){
    log_debug("MacVFN Init");
    bool ret = super::init();
    if (!ret) {
        log_debug("MacVFN: init failed");
        return false;
    }

    ivars = IONewZero(MacVFN_IVars, 1);
    if (!ivars) {
        return false;
    }

    log_debug("MacVFN Init Done!");
    return true;
}

void MacVFN::free(){
    log_debug("MacVFN Free");

    OSSafeReleaseNULL(ivars->ctrl.pci.dev);
    OSSafeReleaseNULL(ivars->ctrl.pci.iommu_mappings);
    OSSafeReleaseNULL(ivars->pciDevice);
    IOSafeDeleteNULL(ivars, MacVFN_IVars, 1);

    super::free();
}

kern_return_t
IMPL(MacVFN, Start)
{
    log_debug("MacVFN: Start");
    kern_return_t ret;
    ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        return kIOReturnNoDevice;
    }

    ivars->pciDevice = OSDynamicCast(IOPCIDevice, provider);
    if (ivars->pciDevice == NULL) {
        Stop(provider);
        return kIOReturnNoDevice;
    }
    ivars->pciDevice->retain();

    ret = ivars->pciDevice->Open(this, 0);
    if (ret != kIOReturnSuccess) {
        Stop(provider);
        return kIOReturnNoDevice;
    }

    for (int qid = 0; qid < MAX_QUEUE_COUNT; qid++){
        bzero((void*)&ivars->sq_buffer_descriptors[qid], sizeof(struct MemoryDescriptorPair));
        bzero((void*)&ivars->cq_buffer_descriptors[qid], sizeof(struct MemoryDescriptorPair));
        ivars->sq_ring_queues[qid] = NULL;
        ivars->cq_ring_queues[qid] = NULL;
    }

    ivars->ctrl = {};
    ivars->ctrl.pci.dev = ivars->pciDevice;
    ivars->ctrl.pci.dev->retain();
    ivars->ctrl.pci.iommu_mappings = OSDictionary::withCapacity(16);
    ::iommu_ctx_init(__iommu_ctx(&ivars->ctrl));

    uint16_t commandRegister;
    ivars->pciDevice->ConfigurationRead16(kIOPCIConfigurationOffsetCommand, &commandRegister);
    commandRegister |= (kIOPCICommandBusMaster | kIOPCICommandMemorySpace);
    ivars->pciDevice->ConfigurationWrite16(kIOPCIConfigurationOffsetCommand, commandRegister);

    int nvme_ret = MacVFN::nvme_init();
    if (nvme_ret) {
        return kIOReturnNoDevice;
    }

    IOServiceName service_name;
    memcpy((void*)service_name, (void*)"MacVFN-", 8);
    memcpy(service_name+7, ivars->ctrl.serial, 20);
    for (int i=0; i < 128; i++){
        if (service_name[i] == ' ') {
            service_name[i] = '\0';
            break;
        }
    }
    service_name[127] = '\0';
    SetName(service_name);

    MacVFN::nvme_close_all();

    log_debug("RegisterService");
    RegisterService();

    log_debug("Driver started!");
    return ret;
}

kern_return_t
IMPL(MacVFN, Stop) {
    log_debug("MacVFN: Stop");

    if (ivars->ctrl.pci.dev) {
        ivars->ctrl.pci.dev->release();
        ivars->ctrl.pci.dev = NULL;
    }

    OSSafeReleaseNULL(ivars->ctrl.pci.iommu_mappings);

    if (ivars->pciDevice) {

        uint16_t commandRegister;
        ivars->pciDevice->ConfigurationRead16(kIOPCIConfigurationOffsetCommand, &commandRegister);
        commandRegister &= ~(kIOPCICommandBusMaster | kIOPCICommandMemorySpace);
        ivars->pciDevice->ConfigurationWrite16(kIOPCIConfigurationOffsetCommand, commandRegister);

        ivars->pciDevice->Close(this, 0);
    }

    return Stop(provider, SUPERDISPATCH);
}

kern_return_t
IMPL(MacVFN, NewUserClient)
{
    log_debug("NewUserClient");
    IOService* client = nullptr;
    kern_return_t ret = kIOReturnSuccess;

    if (ivars->user_clients){
        log_error("UserClient already created. Multiple userclients are not supported at this moment.");
        return kIOReturnError;
    }

    ret = Create(this, "UserClientProperties", &client);
    if (ret != kIOReturnSuccess) {
        log_debug("MacVFNDEXT this->Create: ret %x", ret);
        return ret;
    }

    *userClient = OSDynamicCast(IOUserClient, client);
    if (!(*userClient)) {
        client->release();
        log_debug("MacVFNDEXT userClient error");
        return kIOReturnError;
    }
    ivars->user_clients += 1;

    log_debug("NewUserClient successful");

    return kIOReturnSuccess;
}


static inline kern_return_t libvfn_to_kern_return(int ret){
    if (ret == 0){
        return kIOReturnSuccess;
    }
    else{
        return kIOReturnError;
    }
}

int MacVFN::dma_map_buffer(IOMemoryDescriptor* mem, void *vaddr, size_t len){
    log_debug("MacVFN::dma_map_buffer %p %zx", mem, len);
    uint64_t iova;
    return ::_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl.pci), vaddr, len, &iova, IOMMU_MAP_FIXED_IOVA, (void*) mem);
}

int MacVFN::dma_unmap_buffer(IOMemoryDescriptor* mem, void *vaddr){
    log_debug("MacVFN::dma_unmap_buffer %p", mem);
    return ::iommu_unmap_vaddr(__iommu_ctx(&ivars->ctrl.pci), vaddr, NULL);
}

uint32_t MacVFN::nvme_init()
{
    kern_return_t ret;
    ret = ivars->ctrl.pci.dev->GetBARInfo(kPCIMemoryRangeBAR0, &ivars->ctrl.pci.bar_region_info[0].memory_index, &ivars->ctrl.pci.bar_region_info[0].size, &ivars->ctrl.pci.bar_region_info[0].type);
    if(ret != kIOReturnSuccess) {
        log_debug("bar0 failed");
        return kIOReturnNoDevice;
    }
    log_debug("bar0 info: %x, %llx, %x", ivars->ctrl.pci.bar_region_info[0].memory_index, ivars->ctrl.pci.bar_region_info[0].size, ivars->ctrl.pci.bar_region_info[0].type);

    int nvme_ret = ::nvme_init(&ivars->ctrl, "0000:00:00.0", NULL);
    return libvfn_to_kern_return(nvme_ret);
}

uint32_t MacVFN::nvme_oneshot(NvmeSubmitCmd* cmd, void* vaddr)
{
    kern_return_t ret;

    struct nvme_sq *sq;
    if (cmd->queue_id == 0){
        sq = ivars->ctrl.adminq.sq;
    }
    else{
        sq = &ivars->ctrl.sq[cmd->queue_id];
    }
    log_debug("MacVFN::nvme_oneshot %llx, %llx, %llx", (uint64_t)sq, (uint64_t) cmd->cmd, (uint64_t) cmd->cpl);
    int nvme_ret = ::nvme_sync(&ivars->ctrl, sq, (union nvme_cmd*)&cmd->cmd, vaddr, cmd->dbuf_nbytes, (struct nvme_cqe *) &cmd->cpl);
    return libvfn_to_kern_return(nvme_ret);
}

uint32_t MacVFN::nvme_create_ioqpair(NvmeQueue* queue)
{
    log_debug("nvme_create_ioqpair id: %llu vector: %llu", queue->id, queue->vector);

    if (queue->id > MAX_QUEUE_COUNT){
        log_debug("nvme_create_ioqpair queue id larger than fixed max: %llu/%d", queue->id, MAX_QUEUE_COUNT);
        return kIOReturnBadArgument;
    }

    int ret = ::nvme_create_ioqpair(&ivars->ctrl, queue->id, queue->depth + 1, queue->vector, queue->flags);

    if (ret){
        return kIOReturnError;
    }

    struct MemoryDescriptorPair *sq_ring_desc = &ivars->sq_buffer_descriptors[queue->id];
    struct MemoryDescriptorPair *cq_ring_desc = &ivars->cq_buffer_descriptors[queue->id];
    RingQueue** sq_ring = &ivars->sq_ring_queues[queue->id];
    RingQueue** cq_ring = &ivars->cq_ring_queues[queue->id];

    size_t len;
    len = ::__pgmap((void**)&sq_ring_desc->vaddr, (queue->depth + 1)*sizeof(NvmeSubmitCmd) + sizeof(RingQueue), (void**) &sq_ring_desc->vaddr_descriptor);
    assert(len > 0);
    sq_ring_desc->vaddr_descriptor->retain();
    (*sq_ring) = (RingQueue*)sq_ring_desc->vaddr;
    (*sq_ring)->buffer_size = len;
    (*sq_ring)->depth = queue->depth;

    len = ::__pgmap((void**)&cq_ring_desc->vaddr, (queue->depth + 1)*sizeof(NvmeSubmitCmd) + sizeof(RingQueue), (void**) &cq_ring_desc->vaddr_descriptor);
    assert(len > 0);
    cq_ring_desc->vaddr_descriptor->retain();
    (*cq_ring) = (RingQueue*)cq_ring_desc->vaddr;
    (*cq_ring)->buffer_size = len;
    (*cq_ring)->depth = queue->depth;

    return libvfn_to_kern_return(ret);
}

uint32_t MacVFN::nvme_delete_ioqpair(NvmeQueue* queue)
{
    log_debug("nvme_delete_ioqpair id: %llu", queue->id);

    if (queue->id > MAX_QUEUE_COUNT){
        log_debug("nvme_delete_ioqpair queue id larger than fixed max: %llu/%d", queue->id, MAX_QUEUE_COUNT);
        return kIOReturnBadArgument;
    }

    int ret = ::nvme_delete_ioqpair(&ivars->ctrl, queue->id);

    if (ret){
        return kIOReturnError;
    }

    IOBufferMemoryDescriptor** sq_ring_desc = &ivars->sq_buffer_descriptors[queue->id].vaddr_descriptor;
    IOBufferMemoryDescriptor** cq_ring_desc = &ivars->cq_buffer_descriptors[queue->id].vaddr_descriptor;
    void** sq_ring_vaddr = &ivars->sq_buffer_descriptors[queue->id].vaddr;
    void** cq_ring_vaddr = &ivars->cq_buffer_descriptors[queue->id].vaddr;
    RingQueue** sq_ring = &ivars->sq_ring_queues[queue->id];
    RingQueue** cq_ring = &ivars->cq_ring_queues[queue->id];

    (*sq_ring) = NULL;
    __pgunmap(*sq_ring_vaddr, 0, *(void**)sq_ring_desc);
    *sq_ring_desc = NULL;
    *sq_ring_vaddr = NULL;

    (*cq_ring) = NULL;
    __pgunmap(*cq_ring_vaddr, 0, *(void**)sq_ring_desc);
    *cq_ring_desc = NULL;
    *cq_ring_vaddr = NULL;

    return libvfn_to_kern_return(ret);
}

kern_return_t MacVFN::get_queue_buffer(uint32_t qid, uint32_t sq, IOMemoryDescriptor **memory) {
    IOBufferMemoryDescriptor* buffer;
    if (sq){
        buffer = ivars->sq_buffer_descriptors[qid].vaddr_descriptor;
    }
    else {
        buffer = ivars->cq_buffer_descriptors[qid].vaddr_descriptor;
    }

    if (!buffer){
        log_error("Failed to locate buffer for qid: %x, %x", qid, sq);
        return kIOReturnInvalid;
    }
    *memory = buffer;
    return kIOReturnSuccess;
}


kern_return_t MacVFN::poke(uint32_t sqid, uint32_t cqid, OSDictionary* buffers) {
    kern_return_t ret;
    ret = process_sq(sqid, buffers);
    if (ret != kIOReturnSuccess){
        return ret;
    }
    ret = process_cq(cqid, buffers);
    if (ret != kIOReturnSuccess){
        return ret;
    }

    return kIOReturnSuccess;
}

kern_return_t MacVFN::process_sq(uint32_t qid, OSDictionary* buffers) {
    RingQueue* ring_sq = ivars->sq_ring_queues[qid];

    NvmeSubmitCmd nvme_cmd;
    struct nvme_sq *sq;
    OSNumber* key;
    IOBufferMemoryDescriptor* mem;
    IOBufferMemoryDescriptor* _mem;
    if (qid == 0){
        sq = ivars->ctrl.adminq.sq;
    }
    else{
        sq = &ivars->ctrl.sq[qid];
    }

    log_debug("process_sq: (qid %u) pre queue head/tail %llu/%llu/%llu", qid, ring_sq->head, ring_sq->tail, ring_sq->depth);
    int reaped = 0;
    uint64_t head, tail;
    int entries_ready = queue_dequeue_ready(ring_sq, &head, &tail);
    for (uint64_t i=head; i < head+entries_ready; i++){
        uint64_t next = i % ring_sq->depth;
        queue_get_entry(ring_sq, next, &nvme_cmd);

        struct nvme_rq *rq;
        rq = ::nvme_rq_acquire_atomic(sq);
        rq->opaque = (void*) nvme_cmd.backend_opaque;
        mb();

        uint64_t iova;
        if (nvme_cmd.dbuf_token) {
            key = (OSNumber*) nvme_cmd.dbuf_token;
            OSArray* buf_desc = (OSArray*) buffers->getObject(key);
            if (!buf_desc){
                log_error("MacVFN::process_sq: Invalid dbuf_token!");
                return kIOReturnError;
            }
            IOMemoryDescriptor *buffer = (IOMemoryDescriptor *) buf_desc->getObject(0);
            OSNumber *_vaddr = (OSNumber *) buf_desc->getObject(1);
            uint64_t vaddr = _vaddr->unsigned64BitValue();
            if (::_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl), (void*) vaddr, nvme_cmd.dbuf_nbytes, &iova, IOMMU_MAP_FIXED_IOVA, (void*) buffer)) {
                log_error("FAILED: vfio_iommu_vaddr_to_iova()");
                ::nvme_rq_release_atomic(rq);
                return kIOReturnError;
            }

            if (nvme_cmd.dbuf_offset){
                iova += nvme_cmd.dbuf_offset;
            }

            ::nvme_rq_map_prp(&ivars->ctrl, rq, (union nvme_cmd *)&nvme_cmd.cmd, iova, nvme_cmd.dbuf_nbytes);
        }

        if (nvme_cmd.mbuf_token) {
            key = (OSNumber*) nvme_cmd.mbuf_token;
            OSArray* buf_desc = (OSArray*) buffers->getObject(key);
            if (!buf_desc){
                log_error("MacVFN::process_sq: Invalid mbuf_token!");
                return kIOReturnError;
            }
            IOMemoryDescriptor *buffer = (IOMemoryDescriptor *) buf_desc->getObject(0);
            OSNumber *_vaddr = (OSNumber *) buf_desc->getObject(1);
            uint64_t vaddr = _vaddr->unsigned64BitValue();
            if (::_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl), (void*) vaddr, nvme_cmd.mbuf_nbytes, &iova, IOMMU_MAP_FIXED_IOVA, (void*) buffer)) {
                log_error("FAILED: vfio_iommu_vaddr_to_iova()");
                ::nvme_rq_release_atomic(rq);
                return kIOReturnError;
            }

            if (nvme_cmd.mbuf_offset){
                iova += nvme_cmd.mbuf_offset;
            }

            ((union nvme_cmd*) &nvme_cmd.cmd)->mptr = cpu_to_le64(iova);
        }
        ::nvme_rq_exec(rq, (union nvme_cmd *)&nvme_cmd.cmd);
        log_info("process_sq: opaque %x, %x, %llx", qid, rq->cid, (uint64_t) rq->opaque);
        assert(rq->opaque);
        reaped += 1;
    }

    assert(reaped == entries_ready);

    if (reaped){
        mb();
        uint64_t old_head = __c11_atomic_exchange(&ring_sq->head, (head+reaped) % ring_sq->depth, __ATOMIC_RELAXED);
        assert(old_head == head);
    }
    log_debug("process_sq: post queue head/tail %llu/%llu/%llu", ring_sq->head, ring_sq->tail, ring_sq->depth);

    return kIOReturnSuccess;
}

kern_return_t MacVFN::process_cq(uint32_t qid, OSDictionary* buffers) {
    struct nvme_cq *cq;
    struct nvme_sq *sq;

    if (qid == 0){
        cq = ivars->ctrl.adminq.cq;
        sq = ivars->ctrl.adminq.sq;
    }
    else{
        cq = &ivars->ctrl.cq[qid];
        sq = &ivars->ctrl.sq[qid];
    }

    RingQueue* ring_cq = ivars->cq_ring_queues[qid];
    int reaped = 0;
    NvmeSubmitCmd nvme_cmd;
    while (true) {
        if (queue_full(ring_cq)){
            // Queue full
            break;
        }

        struct nvme_rq *rq;
        struct nvme_cqe *cqe;

        cqe = ::nvme_cq_get_cqe(cq);
        if (!cqe) {
            break;
        }

        reaped++;

        rq = ::__nvme_rq_from_cqe(sq, cqe);
        assert(rq->cid == cqe->cid);
        assert(rq->opaque);
        nvme_cmd.backend_opaque = (uint64_t)rq->opaque;

        memcpy(&nvme_cmd.cpl, cqe, sizeof(nvme_cmd.cpl));
        assert(nvme_cmd.backend_opaque);
        assert(queue_enqueue(ring_cq, &nvme_cmd) == 0);
        mb();
        nvme_rq_release_atomic(rq);
    }

    mb();
    if (reaped) {
        log_debug("process_cq: Updating %d", reaped);
        nvme_cq_update_head(cq);
    }

    return kIOReturnSuccess;
}

void MacVFN::nvme_close_all(){
    ::nvme_close(&ivars->ctrl);

    for (int qid = 0; qid < MAX_QUEUE_COUNT; qid++){
        OSSafeReleaseNULL(ivars->sq_buffer_descriptors[qid].vaddr_descriptor);
        OSSafeReleaseNULL(ivars->cq_buffer_descriptors[qid].vaddr_descriptor);
        ivars->sq_buffer_descriptors[qid].vaddr = NULL;
        ivars->cq_buffer_descriptors[qid].vaddr = NULL;

        // These are derived pointers and are released by the descriptors above
        ivars->sq_ring_queues[qid] = NULL;
        ivars->cq_ring_queues[qid] = NULL;
    }

    log_info("IOMMU Mapping still have %u entries", ivars->ctrl.pci.iommu_mappings->getCount());

    ::iommu_unmap_all(__iommu_ctx(&ivars->ctrl.pci));
}

void MacVFN::stop_userclient(){
    nvme_close_all();
    ivars->user_clients -= 1;
}
