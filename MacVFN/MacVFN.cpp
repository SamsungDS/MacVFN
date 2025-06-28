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
#include "MacVFNBuffers.h"

#include <vfn/nvme.h>
#include "libvfn/src/iommu/context.h"
#include "libvfn/src/nvme/types.h"
#include "libvfn/ccan/ccan/minmax/minmax.h"

#define MAX_QUEUE_COUNT 64

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

    NvmeQueue* block_storage_queue;
    struct DeviceString product_string;
    struct DeviceParams deviceParams;
    IODispatchQueue* default_queue;
    OSAction* interrupt_occured[MAX_QUEUE_COUNT];
    IOInterruptDispatchSource* interrupt_source[MAX_QUEUE_COUNT];
    NVMeBlockStorageCommandContext* block_storage_command_context;

    IOTimerDispatchSource* timer_source;
    OSAction* timer_action;
    uint64_t outstanding;

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
    OSSafeReleaseNULL(ivars->pciDevice);
    IOSafeDeleteNULL(ivars, MacVFN_IVars, 1);

    super::free();
}

kern_return_t MacVFN::ConfigureInterrupts(){
    log_debug("ConfigureInterrupts");
    kern_return_t ret;
    ret = ivars->pciDevice->ConfigureInterrupts(kIOInterruptTypePCIMessagedX, 1, MAX_QUEUE_COUNT, 0);
    if (ret != kIOReturnSuccess) {
        log_debug("ConfigureInterrupts: failed %x", ret);
        return kIOReturnNoDevice;
    }
    for (int interrupt_vector = 0; interrupt_vector < MAX_QUEUE_COUNT; interrupt_vector++){
        // log_debug("vector: %x", interrupt_vector);
        uint64_t interrupt_type;
        if (IOInterruptDispatchSource::GetInterruptType(ivars->pciDevice, interrupt_vector, &interrupt_type) != kIOReturnSuccess){
            // No more interrupts?
            // log_debug("a");
            continue;
        }

        // log_debug("interrupt vector %x found with type: %llx", interrupt_vector, interrupt_type);
        if ((interrupt_type & kIOInterruptTypePCIMessaged) == 0){
            // No more interrupts?
            continue;
        }

        if (IOInterruptDispatchSource::Create(ivars->pciDevice, interrupt_vector, ivars->default_queue, &ivars->interrupt_source[interrupt_vector]) != kIOReturnSuccess) {
            log_debug("failed to create interrupt dispatch source");
            return kIOReturnError;
        }

        if (CreateActionInterruptOccurred(sizeof(uint64_t), &ivars->interrupt_occured[interrupt_vector]) != kIOReturnSuccess) {
            log_debug("failed to create interrupt action");
            return kIOReturnError;
        }

        if (ivars->interrupt_source[interrupt_vector]->SetHandler(ivars->interrupt_occured[interrupt_vector]) != kIOReturnSuccess) {
            log_debug("failed to set interrupt handler");
            return kIOReturnError;
        }

        log_debug("Enable interrupt: %d", interrupt_vector);
        ivars->interrupt_source[interrupt_vector]->SetEnable(true);
    }
    return kIOReturnSuccess;
}


kern_return_t MacVFN::ConfigureTimer(){
    log_debug("ConfigureTimer");
    kern_return_t ret;
    ret = IOTimerDispatchSource::Create(ivars->default_queue, &ivars->timer_source);
    if (ret != kIOReturnSuccess) {
        return ret;
    }

    ret = CreateActionTimerEvent(sizeof(void*), &ivars->timer_action);
    if (ret != kIOReturnSuccess) {
        return ret;
    }

    ret = ivars->timer_source->SetHandler(ivars->timer_action);
    if (ret != kIOReturnSuccess) {
        return ret;
    }
    return kIOReturnSuccess;
}

kern_return_t MacVFN::IdentifyDrive(){
    log_debug("IdentifyDrive");
    kern_return_t ret;
    void *vaddr;
    ssize_t len;
    union nvme_cmd cmd = {};
    IOBufferMemoryDescriptor *vaddr_descriptor;
    len = ::__pgmap(&vaddr, NVME_IDENTIFY_DATA_SIZE, (void**) &vaddr_descriptor);
	if (len < 0) {
		return -1;
    }

    if (_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl), vaddr, len, NULL, IOMMU_MAP_EPHEMERAL, (void**) vaddr_descriptor)) {
		log_error("failed to map vaddr\n");
		return -1;
	}

    cmd.identify = (struct nvme_cmd_identify) {
		.opcode = NVME_ADMIN_IDENTIFY,
		.cns = NVME_IDENTIFY_CNS_CTRL,
	};

    ret = ::nvme_admin(&ivars->ctrl, &cmd, vaddr, len, NULL);
	if (ret) {
		log_error("could not identify ctrl\n");
		return kIOReturnNoDevice;
	}


    memcpy(&ivars->product_string, ((char *) vaddr) + NVME_IDENTIFY_CTRL_SERIAL_NUMBER, NVME_CTRL_SERIAL_LEN);

    size_t product_len = 0;
    // Serial is not guaranteed to be null-terminated, so only stop at space or max length
    while (product_len < NVME_CTRL_SERIAL_LEN && ((char *)&ivars->product_string)[product_len] != ' ') {
        product_len += 1;
    }
    product_len += 1; // Get one space
    memcpy(((char *)&ivars->product_string) + product_len, ((char *) vaddr) + NVME_IDENTIFY_CTRL_SERIAL_NUMBER + NVME_CTRL_SERIAL_LEN, NVME_CTRL_MODEL_LEN);
    while (product_len < NVME_CTRL_MODEL_LEN && ((char *)&ivars->product_string)[product_len] != ' ') {
        product_len += 1;
    }
    ((char *)&ivars->product_string)[product_len] = '\0';
    ((char *)&ivars->product_string)[kMaxDeviceStringLength - 1] = '\0'; // Just for safety


	uint8_t mdts = *(((char *) vaddr) + NVME_IDENTIFY_CTRL_MDTS);
    uint8_t oncs = *(((char *) vaddr) + NVME_IDENTIFY_CTRL_ONCS);
    log_debug("Support DSM: %x", oncs & 0b100);
    log_debug("mdts %x", mdts);
    log_debug("mqes: %x", ivars->ctrl.config.mqes);
    log_debug("max sq %x, max cq %x", ivars->ctrl.config.nsqa+1, ivars->ctrl.config.ncqa+1);

    // Collect information about the drive for GetDeviceParams, queue count etc.
    cmd.identify = (struct nvme_cmd_identify) {
		.opcode = NVME_ADMIN_IDENTIFY,
		.cns = NVME_IDENTIFY_CNS_NS,
        .nsid = 1,
	};

	ret = ::nvme_admin(&ivars->ctrl, &cmd, vaddr, len, NULL);
	if (ret) {
		log_error("could not identify ns\n");
		return kIOReturnNoDevice;
	}

    NVMeIdentifyNamespaceData* ns = (NVMeIdentifyNamespaceData*) vaddr;

    log_debug("NSZE (Namespace Size): %llu", ns->NSZE);
    log_debug("NCAP (Namespace Capacity): %llu", ns->NCAP);
    log_debug("NSUSE (Namespace Utilization): %llu", ns->NSUSE);
    log_debug("NSFEAT (Namespace Features): 0x%02x", ns->NSFEAT);
    log_debug("NLBAF (Number of LBA Formats): %u", ns->NLBAF);
    log_debug("FLBAS (Formatted LBA Size): 0x%02x", ns->FLBAS);

    // NLBAF is zero-based, so the number of LBA formats is NLBAF + 1
    for (int i = 0; i <= ns->NLBAF && i < 16; ++i) {
        log_debug("LBAF[%d]: MS=%u LBADS=%u RP=%u", i, ns->LBAF[i].MS, ns->LBAF[i].LBADS, ns->LBAF[i].RP & 0x3);
    }

    uint64_t selected_lbaf = ns->FLBAS & NVME_IDENTIFY_FLBAS_INDEX_MASK ;
    log_debug("Selected LBA Format: %llx", selected_lbaf);

	uint64_t cap = le64_to_cpu(mmio_read64(ivars->ctrl.regs, NVME_REG_CAP));
	uint8_t mpsmin = NVME_FIELD_GET(cap, CAP_MPSMIN);

    ivars->deviceParams.numOfBlocks = ns->NSZE;

    log_debug("blockSize calculation: FLBAS=%u, LBADS=%u", ns->FLBAS, ns->LBAF[ns->FLBAS].LBADS);
    ivars->deviceParams.blockSize = 1 << ns->LBAF[selected_lbaf].LBADS;
    log_debug("blockSize set to: %u", ivars->deviceParams.blockSize);
    if (mdts == 0) { // Unlimited
        ivars->deviceParams.maxIOSize = (1ull<<32)-1;
    }
    else {
        ivars->deviceParams.maxIOSize = __mps_to_pagesize(mpsmin) << mdts;
    }
    log_debug("Set maxIOSize to %x (mpsmin=%llx, mdts=%x)", ivars->deviceParams.maxIOSize, __mps_to_pagesize(mpsmin), mdts);


    if (!ivars->block_storage_queue) {
        log_error("block_storage_queue is not initialized");
        return kIOReturnNoDevice;
    }
    ivars->deviceParams.numOfOutstandingIOs = ivars->block_storage_queue->depth;
    ivars->deviceParams.minSegmentAlignment = __VFN_PAGESIZE;
    ivars->deviceParams.numOfAddressBits = 48;
    ivars->deviceParams.isUnmapSupported = oncs & 0b100;
    ivars->deviceParams.maxNumOfUnmapRegions = ivars->deviceParams.isUnmapSupported ? 255 : 0;
    ivars->deviceParams.isFUASupported = false; // forced unit access

    return kIOReturnSuccess;
}


kern_return_t
IMPL(MacVFN, Start)
{
    log_debug("MacVFN: Start");
    kern_return_t ret;
    NvmeQueue* new_queue;
    IOServiceName service_name;

    ivars->pciDevice = OSDynamicCast(IOPCIDevice, provider);
    if (ivars->pciDevice == NULL) {
        ret = kIOReturnNoDevice;
        goto fail;
    }
    ivars->pciDevice->retain();

    ret = ivars->pciDevice->Open(this, 0);
    if (ret != kIOReturnSuccess) {
        goto fail;
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
    ::iommu_ctx_init(__iommu_ctx(&ivars->ctrl));

    uint16_t commandRegister;
    ivars->pciDevice->ConfigurationRead16(kIOPCIConfigurationOffsetCommand, &commandRegister);
    commandRegister |= (kIOPCICommandBusMaster | kIOPCICommandMemorySpace);
    ivars->pciDevice->ConfigurationWrite16(kIOPCIConfigurationOffsetCommand, commandRegister);


    if (CopyDispatchQueue(kIOServiceDefaultQueueName, &ivars->default_queue) != kIOReturnSuccess) {
        log_debug("failed to copy queue");
        ret = kIOReturnError;
        goto fail;
    }

    ret = MacVFN::nvme_init();
    if (ret != kIOReturnSuccess) {
        goto fail;
    }

    log_debug("nsqa: %x", ivars->ctrl.config.nsqa);
    log_debug("mqes: %x", ivars->ctrl.config.mqes);
    ivars->outstanding = 0;

    new_queue = IONewZero(NvmeQueue, 1);
    new_queue->id = min(MAX_QUEUE_COUNT-1, ivars->ctrl.config.nsqa+1);
    new_queue->depth = ivars->ctrl.config.mqes;
    new_queue->vector = 5; // NOTE: Just testing, by giving something != 0, 1 or qid
    ivars->block_storage_queue = new_queue;

    ret = MacVFN::IdentifyDrive();
    if (ret != kIOReturnSuccess) {
        goto fail;
    }

    ivars->block_storage_command_context = IONewZero(NVMeBlockStorageCommandContext, new_queue->depth+1);
    if (!ivars) {
        ret = kIOReturnNoMemory;
        goto fail;
    }

    ret = MacVFN::ConfigureInterrupts();
    if (ret != kIOReturnSuccess) {
        goto fail;
    }

    ret = MacVFN::nvme_create_ioqpair(ivars->block_storage_queue);
    if (ret != kIOReturnSuccess){
        log_debug("Create io queue pair failed!");
        goto fail;
    }

    ret = MacVFN::ConfigureTimer();
    if (ret != kIOReturnSuccess) {
        goto fail;
    }

    // NOTE: Start after NVMe is initialized, otherwise we get race-conditions to GetDeviceParams etc.
    ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        goto fail;
    }

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

    // MacVFN::nvme_close_all();

    //OSDictionary *dictionary = OSDynamicCast(OSDictionary, getProvider()->getProperty(kIOPropertyDeviceCharacteristicsKey));
    // if (dictionary) {
    //     OSString *string = OSDynamicCast(OSString, dictionary->getObject(kIOPropertyMediumTypeKey));

    //     if (string) {
    //         if (string->isEqualTo(kIOPropertyMediumTypeSolidStateKey)) {
    //             _solidState = true;
    //         }
    //     }
    // }

    log_debug("RegisterService");
    RegisterService();

    log_debug("Driver started!");
    return ret;
fail:
    log_error("The driver failed to start. ret is: %x", ret);
    Stop(provider);
    return ret;
}

kern_return_t
IMPL(MacVFN, Stop) {
    log_debug("MacVFN: Stop");

    if (ivars->ctrl.pci.dev) {
        ivars->ctrl.pci.dev->release();
        ivars->ctrl.pci.dev = NULL;
    }

    if (ivars->block_storage_queue){
        if (ivars->block_storage_command_context){
            IOSafeDeleteNULL(ivars->block_storage_command_context, NVMeBlockStorageCommandContext, ivars->block_storage_queue->depth+1);
        }
        IOSafeDeleteNULL(ivars->block_storage_queue, NvmeQueue, 1);
    }

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

    if (type != MACVFN_CLIENT_VERSION){
        log_error("NewUserClient client version mismatch! Theirs: %08x Ours: %08x", type, MACVFN_CLIENT_VERSION);
        return kIOReturnError;
    }

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

kern_return_t MacVFN::nvme_init()
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

kern_return_t MacVFN::nvme_oneshot(NvmeSubmitCmd* cmd, void* vaddr)
{
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

kern_return_t MacVFN::nvme_create_ioqpair(NvmeQueue* queue)
{
    log_debug("nvme_create_ioqpair id: %llu vector: %llu", queue->id, queue->vector);

    if (queue->id >= MAX_QUEUE_COUNT){
        log_debug("nvme_create_ioqpair queue id larger than fixed max: %llu (zero-indexed) of max count %d", queue->id, MAX_QUEUE_COUNT);
        return kIOReturnBadArgument;
    }

    int ret = ::nvme_create_ioqpair(&ivars->ctrl, queue->id, queue->depth + 1, queue->vector, queue->flags);

    if (ret){
        return kIOReturnError;
    }

    uint64_t* interrupt_qid = (uint64_t*) ivars->interrupt_occured[queue->vector]->GetReference();
    *interrupt_qid = queue->id;

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

kern_return_t MacVFN::nvme_delete_ioqpair(NvmeQueue* queue)
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


kern_return_t MacVFN::poke(uint32_t sqid, uint32_t cqid, struct buffer* buffers) {
    kern_return_t ret;
    ret = process_sq(sqid, buffers);
    if (ret != kIOReturnSuccess){
        return ret;
    }
    ret = process_cq(cqid);
    if (ret != kIOReturnSuccess){
        return ret;
    }

    return kIOReturnSuccess;
}

kern_return_t MacVFN::process_sq(uint32_t qid, struct buffer* buffers) {
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
            struct buffer* buf = buffer_find(buffers, nvme_cmd.dbuf_token);
            if (!buf){
                log_error("MacVFN::process_sq: Invalid dbuf_token!");
                return kIOReturnError;
            }

            if (::_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl), (void*) buf->vaddr, nvme_cmd.dbuf_nbytes, &iova, IOMMU_MAP_FIXED_IOVA, (void*) buf->buf_desc)) {
                log_error("FAILED: vfio_iommu_vaddr_to_iova()");
                ::nvme_rq_release_atomic(rq);
                return kIOReturnError;
            }

            if (nvme_cmd.dbuf_offset){
                iova += nvme_cmd.dbuf_offset;
            }

            ::nvme_rq_map_prp(&ivars->ctrl, rq, (union nvme_cmd *)&nvme_cmd.cmd, iova, nvme_cmd.dbuf_nbytes);
        }
        else if (nvme_cmd.dbuf_iova) {
            assert(::nvme_rq_map_prp(&ivars->ctrl, rq, (union nvme_cmd *)&nvme_cmd.cmd, nvme_cmd.dbuf_iova, nvme_cmd.dbuf_nbytes) == 0);
        }

        if (nvme_cmd.mbuf_token) {
            struct buffer* buf = buffer_find(buffers, nvme_cmd.mbuf_token);
            if (!buf){
                log_error("MacVFN::process_sq: Invalid mbuf_token!");
                return kIOReturnError;
            }

            if (::_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl), (void*) buf->vaddr, nvme_cmd.mbuf_nbytes, &iova, IOMMU_MAP_FIXED_IOVA, (void*) buf->buf_desc)) {
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

    log_info("reaped == entries_ready, %u == %u", reaped, entries_ready);
    assert(reaped == entries_ready);

    if (reaped){
        log_info("exchange");
        mb();
        uint64_t old_head = __c11_atomic_exchange(&ring_sq->head, (head+reaped) % ring_sq->depth, __ATOMIC_RELAXED);
        assert(old_head == head);
    }
    log_debug("process_sq: post queue head/tail %llu/%llu/%llu", ring_sq->head, ring_sq->tail, ring_sq->depth);

    return kIOReturnSuccess;
}

kern_return_t MacVFN::process_cq(uint32_t qid) {
    log_debug("process_cq: %x", qid);
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
        log_debug("process_cq: while");
        if (queue_full(ring_cq)){
            log_debug("process_cq: queue full");
            // Queue full
            break;
        }

        struct nvme_rq *rq;
        struct nvme_cqe *cqe;

        log_debug("process_cq: get cqe");
        cqe = ::nvme_cq_get_cqe(cq);
        if (!cqe) {
            log_debug("process_cq: no cqe");
            break;
        }

        reaped++;

        log_debug("process_cq: get rq from cqe");
        rq = ::__nvme_rq_from_cqe(sq, cqe);
        assert(rq->cid == cqe->cid);
        assert(rq->opaque);
        nvme_cmd.backend_opaque = (uint64_t)rq->opaque;
        log_debug("process_cq: opaque %llx", nvme_cmd.backend_opaque);

        memcpy(&nvme_cmd.cpl, cqe, sizeof(nvme_cmd.cpl));
        assert(nvme_cmd.backend_opaque);
        log_debug("process_cq: ring_cq queue_enqueue");
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
    // ::nvme_close(&ivars->ctrl);

    // Close all possible queue pairs but the last one, as that's our block storage queue. nsqa is zero-based.
    for (uint64_t qid = 0; qid < ivars->ctrl.config.nsqa; qid++){
        // Check queue is in use before deleting
        if (ivars->sq_ring_queues[qid]){
            NvmeQueue queue = {
                .id = qid,
            };

            MacVFN::nvme_delete_ioqpair(&queue);
        }

        OSSafeReleaseNULL(ivars->sq_buffer_descriptors[qid].vaddr_descriptor);
        OSSafeReleaseNULL(ivars->cq_buffer_descriptors[qid].vaddr_descriptor);
        ivars->sq_buffer_descriptors[qid].vaddr = NULL;
        ivars->cq_buffer_descriptors[qid].vaddr = NULL;

        // These are derived pointers and are released by the descriptors above
        ivars->sq_ring_queues[qid] = NULL;
        ivars->cq_ring_queues[qid] = NULL;
    }

    // ::iommu_unmap_all(__iommu_ctx(&ivars->ctrl.pci));
}

void MacVFN::stop_userclient(){
    nvme_close_all();
    ivars->user_clients -= 1;
}


kern_return_t // (uint32_t requestID)
IMPL(MacVFN, DoAsyncEjectMedia) {
    log_debug("IMPL(MacVFN, DoAsyncEjectMedia) requestID: %x", requestID);

    // TODO: nvme_close_all but also unmap all mappings that **are** from block storage
    ::nvme_close(&ivars->ctrl);
    MacVFN::nvme_close_all();
    // TODO: ::iommu_unmap_all(__iommu_ctx(&ivars->ctrl.pci));
    // TODO: MacVFNUserClient Stop

    MacVFN::Complete(requestID, kIOReturnSuccess);
    return kIOReturnSuccess;
}


kern_return_t // (uint32_t requestID, uint64_t lba, uint64_t numOfBlocks)
IMPL(MacVFN, DoAsyncSynchronize) {
    log_debug("IMPL(MacVFN, DoAsyncSynchronize) requestID: %x lba: %llx numOfBlocks: %llx", requestID, lba, numOfBlocks);

    NVMeSpecIOCommand payload = {
        .opcode = NVME_OPC_FLUSH,
        .cid = 0, // Gets overriden through nvme_rq_exec->nvme_rq_prep_cmd
        .nsid = 1,
    };

    NVMeBlockStorageCommandContext* context = &ivars->block_storage_command_context[requestID];
    context->do_unmap = false;

    assert((OPAQUE_HAS_CONTEXT & ((uint64_t) requestID)) == 0); // Otherwise hacking the opaque doesn't work
    NvmeSubmitCmd cmd = {
        .queue_id = ivars->block_storage_queue->id,
        .backend_opaque = OPAQUE_HAS_CONTEXT | ((uint64_t) requestID),
        .dbuf_nbytes = 0,
        .dbuf_offset = 0,
        .dbuf_token = 0,
        .dbuf_iova = 0,
        .mbuf_nbytes = 0,
        .mbuf_offset = 0,
        .mbuf_token = 0
    };
    static_assert(sizeof(cmd.cmd) == sizeof(payload), "NVMe command size mismatch");
    memcpy(&cmd.cmd, &payload, sizeof(payload));
    log_debug("Prepared NvmeSubmitCmd, sending to block_send_sq");

    MacVFN::block_send_sq(ivars->block_storage_queue->id, &cmd);

    return kIOReturnSuccess;
}

kern_return_t // (bool isRead,
//uint32_t requestID,
//uint64_t dmaAddr,
//uint64_t size,
//uint64_t lba,
//uint64_t numOfBlocks,
//IOUserStorageOptions options)
IMPL(MacVFN, DoAsyncReadWrite) {
    log_debug("IMPL(MacVFN, DoAsyncReadWrite) isRead: %x requestID: %x dmaAddr: %llx size: %llx lba: %llx numOfBlocks: %llx", isRead, requestID, dmaAddr, size, lba, numOfBlocks);
    assert(options == kIOUserStorageOptionNone);
    assert(numOfBlocks < 1<<16);
    assert(numOfBlocks > 0);

    NVMeSpecIOCommand payload = {
        .opcode = isRead ? (uint8_t)NVME_OPC_READ : (uint8_t)NVME_OPC_WRITE,
        .cid = 0, // Gets overriden through nvme_rq_exec->nvme_rq_prep_cmd
        .nsid = 1,
        .slba = lba,
        .nlb = (uint16_t) (numOfBlocks-1) // Zero-based
    };

    NvmeSubmitCmd cmd = {
        .queue_id = ivars->block_storage_queue->id,
        .backend_opaque = (((uint64_t)requestID) << 32) | size,
        .dbuf_nbytes = size,
        .dbuf_offset = 0,
        .dbuf_token = 0,
        .dbuf_iova = dmaAddr,
        .mbuf_nbytes = 0,
        .mbuf_offset = 0,
        .mbuf_token = 0
    };
    static_assert(sizeof(cmd.cmd) == sizeof(payload), "NVMe command size mismatch");
    memcpy(&cmd.cmd, &payload, sizeof(payload));
    MacVFN::block_send_sq(ivars->block_storage_queue->id, &cmd);
    // ivars->timer_source->WakeAtTime(kIOTimerClockMachAbsoluteTime, mach_absolute_time(), 0);

    return kIOReturnSuccess;
}


kern_return_t MacVFN::block_send_sq(uint32_t qid, NvmeSubmitCmd* nvme_cmd) {
    struct nvme_sq *sq;
    assert(qid != 0);
    sq = &ivars->ctrl.sq[qid];

    struct nvme_rq *rq = ::nvme_rq_acquire_atomic(sq);
    assert(rq);
    rq->opaque = (void*) nvme_cmd->backend_opaque;
    mb();

    if (nvme_cmd->dbuf_iova){
        log_debug("nvme_rq_map_prp: ctrl=%p rq=%p cmd=%p iova=0x%llx nbytes=0x%llx",
                  &ivars->ctrl, rq, &nvme_cmd->cmd, nvme_cmd->dbuf_iova, nvme_cmd->dbuf_nbytes);
        assert(::nvme_rq_map_prp(&ivars->ctrl, rq, (union nvme_cmd *)&nvme_cmd->cmd, nvme_cmd->dbuf_iova, nvme_cmd->dbuf_nbytes) == 0);
    }

    ::nvme_rq_exec(rq, (union nvme_cmd *)&nvme_cmd->cmd);
    log_info("block_send_sq: opaque qid:%x, cid:%x, opaque:%llx", qid, rq->cid, (uint64_t) rq->opaque);
    ivars->outstanding += 1;

    return kIOReturnSuccess;
}

int MacVFN::block_recv_cq(uint32_t qid) {
    log_debug("block_recv_cq: %x", qid);
    struct nvme_cq *cq;
    struct nvme_sq *sq;

    assert(qid != 0);
    cq = &ivars->ctrl.cq[qid];
    sq = &ivars->ctrl.sq[qid];

    // RingQueue* ring_cq = ivars->cq_ring_queues[qid];
    int reaped = 0;
    NvmeSubmitCmd nvme_cmd;
    while (true) {
        struct nvme_rq *rq;
        struct nvme_cqe *cqe;

        log_debug("block_recv_cq: get cqe");
        cqe = ::nvme_cq_get_cqe(cq);
        if (!cqe) {
            log_debug("block_recv_cq: no cqe");
            break;
        }

        reaped++;

        log_debug("block_recv_cq: get rq from cqe");
        rq = ::__nvme_rq_from_cqe(sq, cqe);
        assert(rq->cid == cqe->cid);
        log_debug("block_recv_cq: opaque %llx", (uint64_t)rq->opaque);

        uint64_t op = (uint64_t)rq->opaque;
        log_debug("%llx, %llx, %llx, has context: %llx", op, ~OPAQUE_HAS_CONTEXT, op & ~OPAQUE_HAS_CONTEXT, op & OPAQUE_HAS_CONTEXT);

        memcpy(&nvme_cmd.cpl, cqe, sizeof(nvme_cmd.cpl));
        mb();
        nvme_rq_release_atomic(rq);

        log_debug("block_recv_cq status: %x", cqe->sfp>>1);
        if (op & OPAQUE_HAS_CONTEXT){
            uint64_t requestID = op & ~OPAQUE_HAS_CONTEXT;
            NVMeBlockStorageCommandContext* context = &ivars->block_storage_command_context[requestID];

            if (context->do_unmap){
                if (iommu_unmap_vaddr(__iommu_ctx(&ivars->ctrl.pci), (void*)context->address_segment.address, NULL)) {
                    log_error("Failed to do iommu_unmap_vaddr");
                }
            }
            MacVFN::Complete(requestID, (cqe->sfp>>1) == 0 ? kIOReturnSuccess : kIOReturnInvalid);
        }
        else {
            MacVFN::CompleteIO(op >> 32, op & 0xFFFFFFFF, (cqe->sfp>>1) == 0 ? kIOReturnSuccess : kIOReturnInvalid);
        }
    }

    mb();
    if (reaped) {
        log_debug("block_recv_cq: Updating %d", reaped);
        nvme_cq_update_head(cq);
    }

    return reaped;
}

void
IMPL(MacVFN, InterruptOccurred)
{
    log_debug("MacVFNDEXT: InterruptOccurred action: %llx count: %llu time: %llu", (uint64_t) action, count, time);

    uint64_t qid = *(uint64_t*)action->GetReference();
    log_debug("InterruptOccurred qid %llx", qid);
    if (qid == 0) {
        log_debug("Ignoring admin-queue interrupt");
    }
    else{
        ivars->outstanding -= MacVFN::block_recv_cq(qid);
    }
}

void IMPL(MacVFN, TimerEvent)
{
    log_debug("TIMER EVENT!");
    // ivars->outstanding -= MacVFN::block_recv_cq(ivars->ctrl.config.nsqa+1);
    // if (ivars->outstanding){
    //     ivars->timer_source->WakeAtTime(kIOTimerClockMachAbsoluteTime, mach_absolute_time(), 0);
    // }
}


kern_return_t // (struct DeviceParams *deviceParams)
IMPL(MacVFN, GetDeviceParams) {
    log_debug("IMPL(MacVFN, GetDeviceParams)");
    memcpy(deviceParams, &ivars->deviceParams, sizeof(DeviceParams));
    return kIOReturnSuccess;
}

kern_return_t // (struct DeviceString *vendor)
IMPL(MacVFN, GetVendorString) {
    log_debug("IMPL(MacVFN, GetVendorString)");
    strncpy((char*)vendor, "MacVFN ", kMaxDeviceStringLength - 1);
    ((char*)vendor)[kMaxDeviceStringLength - 1] = '\0';
    return kIOReturnSuccess;
}

kern_return_t // (struct DeviceString *product)
IMPL(MacVFN, GetProductString) {
    log_debug("IMPL(MacVFN, GetProductString)");
    strncpy((char*)product, (char*)&ivars->product_string, kMaxDeviceStringLength - 1);
    ((char*)product)[kMaxDeviceStringLength - 1] = '\0';
    return kIOReturnSuccess;
}

kern_return_t // (struct DeviceString *revision)
IMPL(MacVFN, GetRevisionString) {
    log_debug("IMPL(MacVFN, GetRevisionString)");
    strncpy((char*)revision, "v0.1", kMaxDeviceStringLength - 1);
    ((char*)revision)[kMaxDeviceStringLength - 1] = '\0';
    return kIOReturnSuccess;
}

kern_return_t // (struct DeviceString *additionalInfo)
IMPL(MacVFN, GetAdditionalInfoString) {
    log_debug("IMPL(MacVFN, GetAdditionalInfoString)");
    // NOTE: Documented as unused by macOS
    strncpy((char*)additionalInfo, "", kMaxDeviceStringLength - 1);
    ((char*)additionalInfo)[kMaxDeviceStringLength - 1] = '\0';
    return kIOReturnSuccess;
}

kern_return_t // ( bool *isEjectable )
IMPL(MacVFN, ReportEjectability) {
    log_debug("IMPL(MacVFN, ReportEjectability)");
    *isEjectable = true;
    return kIOReturnSuccess;
}

kern_return_t // ( bool *isRemovable )
IMPL(MacVFN, ReportRemovability) {
    log_debug("IMPL(MacVFN, ReportRemovability)");
    *isRemovable = true;
    return kIOReturnSuccess;
}

kern_return_t // ( bool *isWriteProtected )
IMPL(MacVFN, ReportWriteProtection) {
    log_debug("IMPL(MacVFN, ReportWriteProtection)");
    *isWriteProtected = false;
    return kIOReturnSuccess;
}

void // (uint32_t requestID, uint64_t bytesTransferred, kern_return_t IOStatus)
IMPL(MacVFN, CompleteIO) {
    log_debug("IMPL(MacVFN, CompleteIO) request: %x size: %llx", requestID, bytesTransferred);
    // log_debug("CompleteIO");
    CompleteIO(requestID, bytesTransferred, IOStatus, SUPERDISPATCH);
}

void // (uint32_t requestID, kern_return_t status)
IMPL(MacVFN, Complete) {
    log_debug("IMPL(MacVFN, Complete) %x", requestID);
    Complete(requestID, status, SUPERDISPATCH);
}

kern_return_t
IMPL(MacVFN, RegisterDext) {
    log_debug("IMPL(MacVFN, RegisterDext)");
    return kIOReturnSuccess;
}

kern_return_t MacVFN::DoAsyncUnmapPriv(uint32_t requestID, struct BlockRange *ranges, uint32_t numOfRanges) {
    log_debug("MacVFN::DoAsyncUnmapPriv - start %x, numOfRanges:%x", requestID, numOfRanges);

    IOBufferMemoryDescriptor* dsmBuffer = nullptr;
    kern_return_t ret = IOBufferMemoryDescriptor::Create(
        kIOMemoryDirectionInOut,
        numOfRanges * sizeof(NVMeSpecDSMRangeData),
        __VFN_PAGESIZE,
        &dsmBuffer
    );
    log_debug("After IOBufferMemoryDescriptor::Create, ret=%x, dsmBuffer=%p", ret, dsmBuffer);
    if (ret != kIOReturnSuccess || !dsmBuffer) {
        log_error("Failed to allocate DSM buffer");
        return kIOReturnNoMemory;
    }

    IOAddressSegment address_segment;
    ret = dsmBuffer->GetAddressRange(&address_segment);
    log_debug("After GetAddressRange, ret=%x", ret);
    if (ret != kIOReturnSuccess) {
        log_error("Failed to allocate DSM buffer");
        return kIOReturnNoMemory;
    }

    // Get the virtual address of the DSM buffer
    NVMeSpecDSMRangeData* dsm_ranges = (NVMeSpecDSMRangeData*) address_segment.address;
    log_debug("DSM buffer vaddr: %llx, length: %llx", address_segment.address, address_segment.length);

    for (uint32_t i = 0; i < numOfRanges; ++i) {
        struct BlockRange range = ranges[i];
        // Fill DSM range entry
        dsm_ranges[i].CA = 0; // Context Attributes, set as needed
        dsm_ranges[i].NLB = range.numOfBlocks - 1; // zero-based
        dsm_ranges[i].SLBA = range.startBlock;
        log_debug("DSM range[%u]: SLBA=%llx NLB=%x", i, dsm_ranges[i].SLBA, dsm_ranges[i].NLB);
    }

    NVMeSpecDSMCommand payload = {
        .opcode = NVME_OPC_DATASET_MANAGEMENT,
        .cid = 0, // Gets overriden through nvme_rq_exec->nvme_rq_prep_cmd
        .nsid = 1,
        .nr = numOfRanges - 1, // Zero based
        .attributes = 0b100, // Deallocate
    };
    log_debug("DSM payload: opcode=0x%02x cid=0x%04x nsid=0x%08x nr=0x%02x attributes=0x%02x",
              payload.opcode, payload.cid, payload.nsid, payload.nr, payload.attributes);
    log_debug("Prepared DSM command payload");

    // int MacVFN::dma_map_buffer(IOMemoryDescriptor* mem, void *vaddr, size_t len){
    uint64_t iova;
    ret = libvfn_to_kern_return(::_iommu_map_vaddr(__iommu_ctx(&ivars->ctrl.pci), (void *) address_segment.address, address_segment.length, &iova, IOMMU_MAP_FIXED_IOVA, (void*) dsmBuffer));
    if (ret != kIOReturnSuccess) {
        log_error("Failed to do _iommu_map_vaddr");
        return kIOReturnNoMemory;
    }

    NVMeBlockStorageCommandContext* context = &ivars->block_storage_command_context[requestID];
    // context->request_id = requestID;
    context->memory_descriptor = dsmBuffer;
    context->address_segment = address_segment;
    context->size = numOfRanges * sizeof(NVMeSpecDSMRangeData);
    context->do_unmap = true;

    assert((OPAQUE_HAS_CONTEXT & ((uint64_t) requestID)) == 0); // Otherwise hacking the opaque doesn't work
    NvmeSubmitCmd cmd = {
        .queue_id = ivars->block_storage_queue->id,
        .backend_opaque = OPAQUE_HAS_CONTEXT | ((uint64_t) requestID),
        .dbuf_nbytes = numOfRanges * sizeof(NVMeSpecDSMRangeData),
        .dbuf_offset = 0,
        .dbuf_token = 0,
        .dbuf_iova = iova,
        .mbuf_nbytes = 0,
        .mbuf_offset = 0,
        .mbuf_token = 0
    };
    static_assert(sizeof(cmd.cmd) == sizeof(payload), "NVMe command size mismatch");
    memcpy(&cmd.cmd, &payload, sizeof(payload));
    log_debug("Prepared NvmeSubmitCmd, sending to block_send_sq");

    MacVFN::block_send_sq(ivars->block_storage_queue->id, &cmd);

    log_debug("MacVFN::DoAsyncUnmapPriv - end");
    return kIOReturnSuccess;
}