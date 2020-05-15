default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn

CFLAGS:=-I$(TOOLCHAIN_PATH)/include 
CFLAGS:=-I$(SDN_BUILD_DIR)/include -I$(SDN_BUILD_DIR)/usr/include

LDFLAGS+=-L$(TOOLCHAIN_PATH)/lib
LDFLAGS+=-L$(SDN_BUILD_DIR)/lib -L$(SDN_BUILD_DIR)/usr/lib

APP = libubox-3c1b33b
APP_BASE = libubox

#export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
#export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
#export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default $(APP_BASE) clean distclean

# $(SDN_BUILD_DIR) - where to install the dependency files(*.h/*.so) for other moudles
# $(INSTALL_DIR)   - where to install the target files(*.so/EXEC) for ROOT FS
install: $(APP_BASE)
	echo "$(CURR_DIR)/Makefile -->install staging"
	mkdir -p $(SDN_BUILD_DIR)/include/libubox
	mkdir -p $(SDN_BUILD_DIR)/lib
	cp -a $(APP)/*.h   $(SDN_BUILD_DIR)/include/libubox/
	cp -a $(APP)/libubox.so* $(SDN_BUILD_DIR)/lib/
	cp -a $(APP)/libblobmsg_json.so* $(SDN_BUILD_DIR)/lib/
	echo "$(CURR_DIR)/Makefile -->install target"
	mkdir -p $(INSTALL_DIR)/lib
	cp -a $(APP)/libubox.so* $(INSTALL_DIR)/lib/
	cp -a $(APP)/libblobmsg_json.so* $(INSTALL_DIR)/lib/

$(APP_BASE): info
	@if [ ! -e $(APP)/config.log ]; then \
	    echo "Untarring original $(APP) source"; \
	    tar zxf $(APP).tar.gz 2> /dev/null || true; \
	    echo "Building $(APP) to $(SDN_BUILD_DIR)/lib"; \
	    cd $(APP); \
		CFLAGS="$(CFLAGS) " \
		LDFLAGS="$(LDFLAGS) " \
		cmake \
			-DBUILD_LUA=OFF \
			-DBUILD_EXAMPLES=OFF \
			-DCMAKE_SYSTEM_NAME=Linux \
			-DCMAKE_SYSTEM_PROCESSOR=arm \
			-DCMAKE_C_COMPILER=$(CC) \
			-DCMAKE_C_COMPILER_AR=$(AR) \
			-DCMAKE_C_COMPILER_RANLIB=$(RANLIB) \
			-DCMAKE_AR=$(AR) \
			-DCMAKE_NM=$(NM) \
			-DCMAKE_RANLIB=$(RANLIB) \
			-DCMAKE_PREFIX_PATH=$(INSTALL_DIR) ; \
	fi; \
		make -j1
	echo "Done building $(APP_BASE)"

clean:
	-make -C $(APP) clean
	echo "$(CURR_DIR)/Makefile -->clean staging"
	-rm -rf $(SDN_BUILD_DIR)/include/libubox
	-rm -f $(SDN_BUILD_DIR)/lib/libubox.so*
	-rm -f $(SDN_BUILD_DIR)/lib/libblobmsg_json.so*
	echo "$(CURR_DIR)/Makefile -->clean target"
	-rm -f $(INSTALL_DIR)/lib/libubox.so*
	-rm -f $(INSTALL_DIR)/lib/libblobmsg_json.so*

distclean: clean
	-rm -rf $(APP)

info:
	echo "$(curr_dir)/makefile -->info"
	@echo "topdir         = $(topdir)"
	@echo "build_dir      = $(build_dir)"
	@echo "target_dir     = $(target_dir)"
	@echo "staging_dir    = $(staging_dir)"
	@echo "toolchain_prefix= $(toolchain_prefix)"
	@echo "bcm_fsbuild_dir= $(bcm_fsbuild_dir)"
	@echo "sdn_build_dir= $(sdn_build_dir)"
	@echo "install_dir= $(install_dir)"
	@echo "toolchain_dir= $(toolchain_dir)"
	@echo "toolchain_sysroot= $(toolchain_sysroot)"
	@echo "cross   = $(cross)"
	@echo "cross_compile = $(cross_compile)"
	@echo "cc      = $(cc)"
	@echo "ar      = $(ar)"
	@echo "ld      = $(ld)"
	@echo "cflags  = $(cflags)"
	@echo "ldflags = $(ldflags)"


