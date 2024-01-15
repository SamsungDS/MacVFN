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
1. Git clone this repo with submodules: `git clone --recurse-submodules https://github.com/openmpdk/MacVFN.git`
2. Run `make build install kill log`, approve system extension and type sudo-password as needed
3. Clone xNVMe with the `driverkit` branch: `git clone -b driverkit https://github.com/baekalfen/xnvme`
4. Run `make config build install`
5. Check your NVMe device enumerates `./builddir/tools/xnvme enum`
6. Then take the 'uri' and run a command: `./builddir/tools/xnvme idfy 1 --cns 0 --be=driverkit`
7. Or two `./builddir/examples/xnvme_single_sync 1`
8. Or three `./builddir/examples/xnvme_single_async 1`

Optionally, you can clone and build [fio](https://github.com/axboe/fio) with xNVMe support:

1. Git clone fio: `git clone https://github.com/axboe/fio`
2. Install GNU-make: `brew install make`
3. Use `gmake` to build it: `gmake -j`
4. Run a test: `./fio --name=test1 --iodepth=64 --rw=write --bs=512 --size=1GB --loops=1 --numjobs=1 --direct=1 --ioengine=xnvme --filename=1 --thread=1 --xnvme_dev_nsid=1 --xnvme_be=driverkit --xnvme_sync=driverkit  --xnvme_async=driverkit --verify=crc32`
