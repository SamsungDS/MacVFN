# MacVFN (BETA)
This is a port of [libvfn](https://github.com/OpenMPDK/libvfn) for macOS and implemented into [xNVMe](https://github.com/OpenMPDK/xnvme). It utilizes DriverKit to hook an external PCI NVMe device (through PCIDriverKit), and allows user-space applications to take control of the device.

**This is not suitable for production**, as it requires [disabling SIP](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection?language=objc), and everything has to be self-signed. The code might also be buggy or have improper memory management, as this is just a proof-of-concept at this point.

# State of the code
Consider this a beta release. It works fine for prototyping, testing, and development.

Although it's a port of libvfn, there is no way of running any of the example code from the libvfn project, as they heavily depend on Linux-only APIs. Instead, MacVFN has been implemented in xNVMe as a reference solution. All the examples from xNVMe should work.

## TODO list:

* Interrupts
* Timeouts
* Register with [BlockStorageDeviceDriverKit](https://developer.apple.com/documentation/blockstoragedevicedriverkit)

# Installation

These are the basic steps to build and install the driver:

0. [Disable SIP](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection?language=objc)
1. Run `systemextensionsctl developer on` to [allow System Extensions from any directory](https://developer.apple.com/documentation/driverkit/debugging_and_testing_system_extensions)
2. Identify the newest or matching tagged xNVMe version of MacVFN (or go with `master`)
3. Git clone this repo with submodules: `git clone --recurse-submodules --branch xnvme_vX.Y.Z https://github.com/SamsungDS/MacVFN.git`
4. Run `make build install kill log`, approve system extension and type sudo-password as needed
5. Clone xNVMe with the `driverkit` branch: `git clone -b driverkit https://github.com/baekalfen/xnvme`
6. Run `make config build install`
7. Check your NVMe device enumerates `xnvme enum`
8. Then take the 'uri' and run a command: `xnvme idfy MacVFN-1234ABCD --cns 0 --be=driverkit`
9. Or two `xnvme_single_sync MacVFN-1234ABCD`
10. Or three `xnvme_single_async MacVFN-1234ABCD`

Optionally, you can clone and build [fio](https://github.com/axboe/fio) with xNVMe support:

1. Git clone fio: `git clone https://github.com/axboe/fio`
2. Install GNU-make: `brew install make`
3. Use `gmake` to build it: `gmake -j`
4. Run a test: `./fio --name=test1 --iodepth=64 --rw=write --bs=512 --size=1GB --loops=1 --numjobs=1 --direct=1 --ioengine=xnvme --filename=MacVFN-1234ABCD --thread=1 --xnvme_dev_nsid=1 --xnvme_be=driverkit --xnvme_sync=driverkit  --xnvme_async=driverkit --verify=crc32`
