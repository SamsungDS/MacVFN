.PHONY: build-driver log

all: build

BUILD_CONFIG := "Debug"
# BUILD_CONFIG := "Release"
APP := ${HOME}/Library/Developer/Xcode/DerivedData/MacVFN-*/Build/Products/${BUILD_CONFIG}/MacVFN.app
LIBVFN := MacVFN/libvfn

build: ${LIBVFN}/build/ccan/config.h ${LIBVFN}/src/nvme/crc64table.h build-driver

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
	xcodebuild -scheme MacVFN build -configuration ${BUILD_CONFIG}

log:
	@echo "Logging..."
	log stream | grep 'MacVFN'

clean:
	rm -rf ${LIBVFN}/build
	rm ${LIBVFN}/src/nvme/crc64table.h
	xcodebuild clean
