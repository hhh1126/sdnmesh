#############################################################
#
# AL Entity
#
#############################################################
#The C compiler identification is GNU 4.2.1
#Note: I think never use this oldest version
#TARGET_CROSS ?= /usr/local/ARC/gcc/bin/arc-linux-uclibc-

#The C compiler identification is GNU 4.2.3
#Note: Default use in topaz platform
#TARGET_CROSS ?= /usr/local/ARC/arcp1/uclibc/bin/arc-linux-uclibc-

#The C compiler identification is GNU 4.8.0
#Note: Default use in pearl platform

#Note: SDK_DIR should be specified by user's compiled SDK environment

PWD := $(shell pwd)
PRPLMESH_VERSION := 0.1
PRPLMESH_SOURCE_DIR := $(PWD)
PRPLMESH_BUILD_DIR := $(PWD)/build
TARGET_CFLAGS := -fpic -g -Werror -Wall -D_GNU_SOURCE -DSPARTAN_PLATFORM
CMAKE ?= cmake

ifneq ($(CROSS), )
export CC := $(CROSS)gcc
export AR := $(CROSS)ar
export RANLIB := $(CROSS)ranlib
export STRIP  := $(CROSS)strip
CMAKE += -DCMAKE_AR="$(AR)" -DCMAKE_RANLIB="$(RANLIB)" -DCMAKE_STRIP="$(STRIP)"
endif

#Note: This is necessary for cross compile when use pkg-config host tools
export PKG_CONFIG_SYSROOT_DIR=$(STAGING_DIR)
export PKG_CONFIG_LIBDIR="$(STAGING_DIR)/lib/pkgconfig:$(STAGING_DIR)/usr/lib/pkgconfig"

#Note: SYSROOT is important for cross compile to indicate basic library path of toolchain
#if SYSROOT not specify external, then using following logic by default
ifeq ($(SYSROOT), )
GCC_SUPPORT_PRINT_SYSROOT := $(shell $(CC) --help | grep "\-print\-sysroot")
ifneq ($(GCC_SUPPORT_PRINT_SYSROOT), )
#Note: Record sysroot dir by -print-sysroot if gcc support
SYSROOT := $(shell $(CC) -print-sysroot)
else
#Note: Default use libc.so dirname for older version gcc which not support -print-sysroot
SYSROOT := $(shell $(CC) -print-file-name=libc.so | xargs dirname | xargs dirname)
endif
endif

.PHONY: all clean

all: prplmesh

prplmesh_generate_patch:
	mkdir -p patchs
	git diff > patchs/prplmesh_0.9_qtn.patch


$(STAGING_DIR):
	@test -d $(STAGING_DIR) || \
	(echo "Error: Need to build $(STAGING_DIR) is wrong"; false)

$(TARGET):
	@test -d $(TARGET) || \
	(echo "Error: Need to build $(TARGET) is wrong"; false)

prplmesh_cmake: $(STAGING_DIR)
	mkdir -p $(PRPLMESH_BUILD_DIR)
	(cd $(PRPLMESH_BUILD_DIR); \
	$(CMAKE) \
	-DCMAKE_C_FLAGS="$(CFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include" \
	-DCMAKE_EXE_LINKER_FLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
	-DCMAKE_PREFIX_PATH="$(STAGING_DIR);$(STAGING_DIR)/usr" \
	-DCMAKE_FIND_ROOT_PATH="$(SYSROOT)" \
	-DCMAKE_INSTALL_PREFIX="$(STAGING_DIR)" -DQDOCK=1 -DFLAVOUR="qsr1000"	\
	$(PRPLMESH_SOURCE_DIR))

prplmesh: prplmesh_cmake
	$(MAKE) -C $(PRPLMESH_BUILD_DIR) VERBOSE=1

install: prplmesh $(TARGET)
	$(MAKE) -C $(PRPLMESH_BUILD_DIR) VERBOSE=1 install
	install -m0755 -D $(STAGING_DIR)/bin/al_entity $(TARGET)/usr/sbin/al_entity

clean:
	rm -f $(TARGET)/usr/sbin/al_entity
	rm -rf $(STAGING_DIR)/include/prplMesh
	rm -f $(STAGING_DIR)/lib/cmake/prplMesh*.*
	rm -f $(STAGING_DIR)/lib/libprplMesh.a
	rm -f $(STAGING_DIR)/bin/al_entity
	rm -f $(STAGING_DIR)/bin/hl_entity
	rm -rf $(PRPLMESH_BUILD_DIR)

