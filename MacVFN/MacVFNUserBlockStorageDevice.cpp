//
//  MacVFNUserBlockStorageDevice.cpp
//  MacVFN
//
//  Created by David Westerhoff on 2/6/25.
//  See: https://github.com/apple-open-source/macos/blob/8ecaeeea2e342177fc8d87238569f3634efb26ad/IOStorageFamily/IOUserBlockStorageDevice_kext.cpp#L280 for kernel implementation
//  Docs: https://developer.apple.com/documentation/blockstoragedevicedriverkit/iouserblockstoragedevice

#include "MacVFNUserBlockStorageDevice.h"

bool MacVFNUserBlockStorageDevice::init()
{
    return true;
}

void MacVFNUserBlockStorageDevice::free()
{
    // do nothing
}

kern_return_t
IMPL(MacVFNUserBlockStorageDevice, Start) {
    return KERN_SUCCESS;
}

kern_return_t
IMPL(MacVFNUserBlockStorageDevice, Stop) {
    return KERN_SUCCESS;
}

kern_return_t // (uint32_t requestID)
IMPL(MacVFNUserBlockStorageDevice, DoAsyncEjectMedia) {
    return KERN_SUCCESS;
}


kern_return_t // (uint32_t requestID, uint64_t lba, uint64_t numOfBlocks)
IMPL(MacVFNUserBlockStorageDevice, DoAsyncSynchronize) {
    return KERN_SUCCESS;
}

kern_return_t // (uint32_t requestID, IOMemoryDescriptor *buffer, uint32_t numOfRanges)
IMPL(MacVFNUserBlockStorageDevice, DoAsyncUnmap) {
    return KERN_SUCCESS;
}

kern_return_t // (bool isRead,
//uint32_t requestID,
//uint64_t dmaAddr,
//uint64_t size,
//uint64_t lba,
//uint64_t numOfBlocks,
//IOUserStorageOptions options)
IMPL(MacVFNUserBlockStorageDevice, DoAsyncReadWrite) {
    return KERN_SUCCESS;
}

kern_return_t // (struct DeviceParams *deviceParams)
IMPL(MacVFNUserBlockStorageDevice, GetDeviceParams) {
    return KERN_SUCCESS;
}

kern_return_t // (struct DeviceString *vendor)
IMPL(MacVFNUserBlockStorageDevice, GetVendorString) {
    return KERN_SUCCESS;
}

kern_return_t // (struct DeviceString *product)
IMPL(MacVFNUserBlockStorageDevice, GetProductString) {
    return KERN_SUCCESS;
}

kern_return_t // (struct DeviceString *revision)
IMPL(MacVFNUserBlockStorageDevice, GetRevisionString) {
    return KERN_SUCCESS;
}

kern_return_t // (struct DeviceString *additionalInfo)
IMPL(MacVFNUserBlockStorageDevice, GetAdditionalInfoString) {
    return KERN_SUCCESS;
}

kern_return_t // ( bool *isEjectable )
IMPL(MacVFNUserBlockStorageDevice, ReportEjectability) {
    return KERN_SUCCESS;
}

kern_return_t // ( bool *isRemovable )
IMPL(MacVFNUserBlockStorageDevice, ReportRemovability) {
    return KERN_SUCCESS;
}

kern_return_t // ( bool *isWriteProtected )
IMPL(MacVFNUserBlockStorageDevice, ReportWriteProtection) {
    return KERN_SUCCESS;
}

void // (uint32_t requestID, uint64_t bytesTransferred, kern_return_t IOStatus)
IMPL(MacVFNUserBlockStorageDevice, CompleteIO) {
    
}

void // (uint32_t requestID, kern_return_t status)
IMPL(MacVFNUserBlockStorageDevice, Complete) {
    
}

kern_return_t
IMPL(MacVFNUserBlockStorageDevice, RegisterDext) {
    return KERN_SUCCESS;
}

kern_return_t MacVFNUserBlockStorageDevice::DoAsyncUnmapPriv(uint32_t requestID, struct BlockRange *ranges, uint32_t numOfRanges) {
    return kIOReturnSuccess;
}
