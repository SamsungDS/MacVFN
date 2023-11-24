.PHONY: kill build-driver install log

all: build

# BUILD_CONFIG := Debug
BUILD_CONFIG := Release
_APP := $(shell xcodebuild -project MacVFN.xcodeproj -scheme MacVFNInstaller -configuration ${BUILD_CONFIG} -showBuildSettings | grep TARGET_BUILD_DIR | grep -oEi "\/.*")
APP = ${_APP}/MacVFNInstaller.app
LIBVFN := MacVFN/libvfn

kill:
	@echo "Kill..."
	sudo killall com.openmpdk.MacVFN;:
	sudo killall lldb;:

build: ${LIBVFN}/build/ccan/config.h ${LIBVFN}/src/nvme/crc64table.h build-driver sign-driver

${LIBVFN}/build/ccan/config.h:
	rm -rf ${LIBVFN}/build
	cd ${LIBVFN}; meson setup build -Dlibnvme=disabled
	sed -i '' '/HAVE_BUILTIN_TYPES_COMPATIBLE_P/d' ${LIBVFN}/build/ccan/config.h

${LIBVFN}/src/nvme/crc64table.h:
	clang ${LIBVFN}/lib/gentable-crc64.c -I ${LIBVFN}/build/ccan/ -I ${LIBVFN}/ccan/ -o gentable_crc64
	./gentable_crc64 > ${LIBVFN}/src/nvme/crc64table.h
	rm gentable_crc64

build-driver:
	@echo "Building..."
	xcodebuild -scheme MacVFNInstaller build -configuration ${BUILD_CONFIG}

sign-driver:
	@echo "Signing..."
	codesign -s - -f --entitlements "MacVFN/MacVFN.entitlements" "${APP}/Contents/Library/SystemExtensions/com.openmpdk.MacVFN.dext"
	codesign -s - -f --entitlements "MacVFNInstaller/MacVFNInstaller.entitlements" "${APP}"

install:
	@echo "Installing..."
	${APP}/Contents/MacOS/MacVFNInstaller

log:
	@echo "Logging..."
	log stream | grep 'MacVFN'

clean:
	rm -rf ${LIBVFN}/build
	rm ${LIBVFN}/src/nvme/crc64table.h
	xcodebuild clean
