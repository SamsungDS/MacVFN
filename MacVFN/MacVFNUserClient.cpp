//
//  MacVFNUserClient.cpp
//  MacVFN
//
//  Created by Mads Ynddal on 24/11/2023.
//

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOLib.h>
#include <DriverKit/OSData.h>
#include <DriverKit/OSDictionary.h>
#include <DriverKit/OSNumber.h>
#include <PCIDriverKit/PCIDriverKit.h>

#include "MacVFN.h"
#include "MacVFNUserClient.h"
#include "MacVFNShared.h"

#include <vfn/support/log.h>

struct MacVFNUserClient_IVars
{
    MacVFN* macvfn = nullptr;
    size_t buffer_count = 0;
    OSDictionary* buffers;
};

bool MacVFNUserClient::init(){
    log_debug("MacVFNUserClient Init");
    kern_return_t result = super::init();
    if(result != true)
    {
        log_debug("MacVFNUserClient: init failed");
        return false;
    }

    ivars = IONewZero(MacVFNUserClient_IVars, 1);
    if(ivars == NULL)
    {
        log_debug("MacVFNUserClient: ivars failed");
        return false;
    }

    ivars->buffers = OSDictionary::withCapacity(16);
    log_debug("MacVFNUserClient Init Done!");
    return true;
}

void MacVFNUserClient::free(){
    log_debug("MacVFNUserClient Free");
    ivars->buffers->release();
    IOSafeDeleteNULL(ivars, MacVFNUserClient_IVars, 1);
    super::free();
}

kern_return_t
IMPL(MacVFNUserClient, Start)
{
    log_debug("MacVFNUserClient: Start");
    kern_return_t ret;
    ret = Start(provider, SUPERDISPATCH);
    if(ret != kIOReturnSuccess)
    {
        return kIOReturnNoDevice;
    }

    ivars->macvfn = OSDynamicCast(MacVFN, provider);
    if(ivars->macvfn == NULL)
    {
        log_debug("MacVFNUserClient: Failed to cast provider");
        Stop(provider);
        return kIOReturnNoDevice;
    }

    return kIOReturnSuccess;
}

kern_return_t
IMPL(MacVFNUserClient, Stop) {
    log_debug("MacVFNUserClient Stop");

    log_info("Buffers still have %u entries", ivars->buffers->getCount());
    OSArray* to_free = OSArray::withCapacity(16);
    ivars->buffers->iterateObjects(^bool (OSObject *key, OSObject *buf_desc){
        log_debug("Missing buffer release: %llx", (uint64_t) key);
        to_free->setObject(key);
        return 0;
    });

    OSNumber *key;
    while (key = (OSNumber *) to_free->getObject(0)){
        OSArray* buf_desc = (OSArray*) ivars->buffers->getObject(key);
        if (!buf_desc){
            log_error("MacVFNUserClient Stop: Tried to dealloc buffer with token: %llx", (uint64_t)key);
            return kIOReturnError;
        }
        IOMemoryDescriptor *buffer = (IOMemoryDescriptor *) buf_desc->getObject(0);
        OSNumber *_vaddr = (OSNumber *) buf_desc->getObject(1);

        log_debug("Attempt dma_unmap_buffer. Buffer might not be mapped, but that's ok.");
        ivars->macvfn->dma_unmap_buffer(buffer, (void*) _vaddr->unsigned64BitValue());

        ivars->buffers->removeObject(key);
        // buffer->release();
        key->release();
        _vaddr->release();
        to_free->removeObject(0);
    }
    to_free->release();

    ivars->macvfn->stop_userclient();

    return Stop(provider, SUPERDISPATCH);
}

kern_return_t
IMPL(MacVFNUserClient, CopyClientMemoryForType) //(uint64_t type, uint64_t *options, IOMemoryDescriptor **memory)
{
    log_debug("IMPL(MacVFNUserClient, CopyClientMemoryForType): %llx -> %llx", (uint64_t) memory, (uint64_t) *memory);

    // https://developer.apple.com/documentation/driverkit/iouserclient/3325615-copyclientmemoryfortype
    // "For a given IOUserClient instance, calling CopyClientMemoryForType() with
    // a given type, should return the same IOMemoryDescriptor instance"

    uint32_t qid = type & 0xFFFF;
    uint32_t sq = (type >> 16) & 1; // True if sq else cq

    return ivars->macvfn->get_queue_buffer(qid, sq, memory);
}

const IOUserClientMethodDispatch externalMethodChecks[NUMBER_OF_EXTERNAL_METHODS] = {
    [NVME_INIT] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmeInit,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = 0,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
    [NVME_ONESHOT] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmeOneshot,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = sizeof(NvmeSubmitCmd),
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = sizeof(NvmeSubmitCmd),
    },
    [NVME_CREATE_QUEUE_PAIR] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmeCreateQueuePair,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = sizeof(NvmeQueue),
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = sizeof(NvmeQueue),
    },
    [NVME_DELETE_QUEUE_PAIR] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmeDeleteQueuePair,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = sizeof(NvmeQueue),
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
    [NVME_ALLOC_BUFFER] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmeAllocBuffer,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = kIOUserClientVariableStructureSize,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 8,
    },
    [NVME_DEALLOC_BUFFER] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmeDeallocBuffer,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = 8,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
    [NVME_POKE] =
    {
        .function = (IOUserClientMethodFunction) &MacVFNUserClient::StaticHandleNvmePoke,
        .checkCompletionExists = false,
        .checkScalarInputCount = 2,
        .checkStructureInputSize = 0,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
};

kern_return_t MacVFNUserClient::ExternalMethod(uint64_t selector, IOUserClientMethodArguments* arguments, const IOUserClientMethodDispatch* dispatch, OSObject* target, void* reference)
{
    kern_return_t ret = kIOReturnSuccess;
    log_debug("MacVFNUserClient ExternalMethod %llu", selector);

    if (selector < NUMBER_OF_EXTERNAL_METHODS) {
        dispatch = &externalMethodChecks[selector];
        if (!target) {
            target = this;
        }
    }
    return super::ExternalMethod(selector, arguments, dispatch, target, reference);
}

kern_return_t MacVFNUserClient::StaticHandleNvmeInit(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmeInit");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmeInit: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmeInit(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmeInit(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret = kIOReturnSuccess;
    log_debug("MacVFNUserClient HandleNvmeInit");
    ivars->macvfn->nvme_init();
    log_debug("MacVFNUserClient HandleNvmeInit Done");
    return ret;
}

kern_return_t MacVFNUserClient::StaticHandleNvmeOneshot(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmeOneshot");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmeOneshot: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmeOneshot(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmeOneshot(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret = kIOReturnSuccess;

    log_debug("MacVFNUserClient HandleNvmeOneshot");
    NvmeSubmitCmd* nvme_cmd = (NvmeSubmitCmd*)arguments->structureInput->getBytesNoCopy();

    log_debug("nvme_cmd->dbuf_token %llx", nvme_cmd->dbuf_token);
    OSNumber* key = (OSNumber*) nvme_cmd->dbuf_token;
    OSArray* buf_desc = (OSArray*) ivars->buffers->getObject(key);
    if (!buf_desc){
        log_error("MacVFN::nvme_oneshot: Invalid dbuf_token!");
    }
    IOMemoryDescriptor *buffer = (IOMemoryDescriptor *) buf_desc->getObject(0);
    OSNumber *_vaddr = (OSNumber *) buf_desc->getObject(1);

    uint64_t vaddr = _vaddr->unsigned64BitValue();
    vaddr += nvme_cmd->dbuf_offset;

    log_debug("MacVFNUserClient HandleNvmeOneshot IOBufferMemoryDescriptor: %p, %llx", buffer, vaddr);
    uint64_t nvme_ret = ivars->macvfn->nvme_oneshot(nvme_cmd, (void*) vaddr);
    log_debug("MacVFNUserClient HandleNvmeOneshot: %llu", nvme_ret);

    arguments->structureOutput = OSData::withBytes(nvme_cmd, sizeof(NvmeSubmitCmd));
    log_debug("MacVFNUserClient HandleNvmeOneshot Done");
    return ret;
}

kern_return_t MacVFNUserClient::StaticHandleNvmeCreateQueuePair(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmeCreateQueuePair");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmeCreateQueuePair: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmeCreateQueuePair(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmeCreateQueuePair(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret;

    log_debug("MacVFNUserClient HandleNvmeCreateQueuePair");
    NvmeQueue* queue = (NvmeQueue*)arguments->structureInput->getBytesNoCopy();

    ret = ivars->macvfn->nvme_create_ioqpair(queue);
    log_debug("MacVFNUserClient HandleNvmeCreateQueuePair: %d", ret);

    arguments->structureOutput = OSData::withBytes(queue, sizeof(NvmeQueue));
    log_debug("MacVFNUserClient HandleNvmeCreateQueuePair Done");
    return ret;
}

kern_return_t MacVFNUserClient::StaticHandleNvmeDeleteQueuePair(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmeDeleteQueuePair");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmeDeleteQueuePair: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmeDeleteQueuePair(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmeDeleteQueuePair(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret;

    log_debug("MacVFNUserClient HandleNvmeDeleteQueuePair");
    NvmeQueue* queue = (NvmeQueue*)arguments->structureInput->getBytesNoCopy();

    ret = ivars->macvfn->nvme_delete_ioqpair(queue);
    log_debug("MacVFNUserClient HandleNvmeDeleteQueuePair: %d", ret);

    // arguments->structureOutput = OSData::withBytes(queue, sizeof(NvmeQueue));
    log_debug("MacVFNUserClient HandleNvmeDeleteQueuePair Done");
    return ret;
}

kern_return_t MacVFNUserClient::StaticHandleNvmeAllocBuffer(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmeAllocBuffer");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmeAllocBuffer: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmeAllocBuffer(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmeAllocBuffer(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret = kIOReturnSuccess;
    log_debug("MacVFNUserClient HandleNvmeAllocBuffer");

    if (arguments->structureInput){
        return kIOReturnInvalid;
    }

    IOMemoryDescriptor *buffer = (IOMemoryDescriptor*)arguments->structureInputDescriptor;
    log_debug("MacVFNUserClient HandleNvmeAllocBuffer IOMemoryDescriptor: %lx", (uintptr_t)buffer);

    IOMemoryMap* map;
    buffer->CreateMapping(0, 0, 0, 0, 0, &map);
    uint64_t vaddr = map->GetAddress();
    size_t nbytes = ((uint64_t*) vaddr)[0];
    // NOTE: We keep the vaddr just for iommu lookups. We actually never read/write the buffer.
    // map->release();

    OSNumber* key = OSNumber::withNumber((uint64_t)ivars->buffer_count, (size_t)64); // Meaningless object to feed to setObject and use as reference later
    // key->retain();

    OSArray* buf_desc = OSArray::withCapacity(2);
	OSNumber* _vaddr = OSNumber::withNumber(vaddr, 64);
	buf_desc->setObject(0, buffer);
	buf_desc->setObject(1, _vaddr);
    ivars->buffers->setObject(key, buf_desc);

    uint64_t token = (uint64_t) key;
    ivars->buffer_count += 1; // Meaningless counter

    log_debug("MacVFNUserClient HandleNvmeAllocBuffer token %llx", token);
    arguments->structureOutput = OSData::withBytes(&token, sizeof(token));

    if (ivars->macvfn->dma_map_buffer(buffer, (void*) vaddr, nbytes)) {
        return kIOReturnError;
    }

    log_debug("MacVFNUserClient HandleNvmeAllocBuffer Done");
    return ret;
}


kern_return_t MacVFNUserClient::StaticHandleNvmeDeallocBuffer(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmeDeallocBuffer");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmeDeallocBuffer: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmeDeallocBuffer(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmeDeallocBuffer(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret = kIOReturnSuccess;
    log_debug("MacVFNUserClient HandleNvmeDeallocBuffer");

    uint64_t token = *(uint64_t*)arguments->structureInput->getBytesNoCopy();
    OSNumber* key = (OSNumber*) token;

    log_debug("MacVFNUserClient HandleNvmeDeallocBuffer key: %llx", (uint64_t)key);

    OSArray* buf_desc = (OSArray*) ivars->buffers->getObject(key);
    if (!buf_desc){
        log_error("MacVFNUserClient HandleNvmeDeallocBuffer: Tried to dealloc buffer with token: %llx", (uint64_t)key);
        return kIOReturnError;
    }
    IOMemoryDescriptor *buffer = (IOMemoryDescriptor *) buf_desc->getObject(0);
    OSNumber *_vaddr = (OSNumber *) buf_desc->getObject(1);
    if (!buffer){
        log_error("MacVFNUserClient HandleNvmeDeallocBuffer: Tried to dealloc buffer with token: %llx", (uint64_t)key);
        return kIOReturnError;
    }

    log_debug("Attept dma_unmap_buffer. Buffer might not be mapped, but that's ok.");
    if (ivars->macvfn->dma_unmap_buffer(buffer, (void*) _vaddr->unsigned64BitValue())) {
        log_error("Internal error in dma_unmap_buffer");
        return kIOReturnError;
    }

    ivars->buffers->removeObject(key);
    // buffer->release();
    key->release();

    log_debug("MacVFNUserClient HandleNvmeDeallocBuffer Done");
    return ret;
}

kern_return_t MacVFNUserClient::StaticHandleNvmePoke(OSObject* target, void* reference, IOUserClientMethodArguments* arguments)
{
    log_debug("MacVFNUserClient StaticHandleNvmePoke");
    if (target == nullptr) {
        log_debug("MacVFNUserClient StaticHandleNvmePoke: Target null");
        return kIOReturnError;
    }

    return ((MacVFNUserClient*)target)->HandleNvmePoke(reference, arguments);
}

kern_return_t MacVFNUserClient::HandleNvmePoke(void* reference, IOUserClientMethodArguments* arguments)
{
    kern_return_t ret = ivars->macvfn->poke(arguments->scalarInput[0], arguments->scalarInput[1], ivars->buffers);
    return ret;
}