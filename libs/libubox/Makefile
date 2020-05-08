default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn

CFLAGS:=-I$(TOOLCHAIN_PATH)/include -I$(TOOLCHAIN_PATH)/usr/include 
CFLAGS:=-I$(SDN_BUILD_DIR)/include -I$(SDN_BUILD_DIR)/usr/include

LDFLAGS+=-L$(TOOLCHAIN_PATH)/lib -L$(TOOLCHAIN_PATH)/usr/lib
LDFLAGS+=-L$(SDN_BUILD_DIR)/lib -L$(SDN_BUILD_DIR)/usr/lib

APP = libubox-3c1b33b
APP_BASE = libubox-3c1b33b

#export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
#export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
#export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default $(APP_BASE) clean distclean

install: $(APP_BASE)
	mkdir -p $(SDN_BUILD_DIR)/include/libubox/
	cp -a $(APP)/*.h   $(SDN_BUILD_DIR)/include/libubox/
	cp -a $(APP)/*.so* $(SDN_BUILD_DIR)/lib/
	cp -a $(APP)/*.a* $(SDN_BUILD_DIR)/lib/
	cp -a $(APP)/*.so* $(INSTALL_DIR)/lib/


info:
	@echo " "
	@echo "hhutest -->info"
	@echo "TOPDIR         = $(TOPDIR)"
	@echo "BUILD_DIR      = $(BUILD_DIR)"
	@echo "TARGET_DIR     = $(TARGET_DIR)"
	@echo "STAGING_DIR    = $(STAGING_DIR)"
	@echo "TOOLCHAIN_PREFIX= $(TOOLCHAIN_PREFIX)"
	@echo "BCM_FSBUILD_DIR= $(BCM_FSBUILD_DIR)"
	@echo "SDN_BUILD_DIR= $(SDN_BUILD_DIR)"
	@echo "INSTALL_DIR= $(INSTALL_DIR)"
	@echo "TOOLCHAIN_DIR= $(TOOLCHAIN_DIR)"
	@echo "TOOLCHAIN_SYSROOT= $(TOOLCHAIN_SYSROOT)"
	@echo "CROSS   = $(CROSS)"
	@echo "CROSS_COMPILE = $(CROSS_COMPILE)"
	@echo "CC      = $(CC)"
	@echo "AR      = $(AR)"
	@echo "LD      = $(LD)"
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(LDFLAGS)"
	@echo "info print "

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
	-rm -f $(INSTALL_DIR)/lib/$(APP_BASE).so*

distclean: clean
	-rm -rf $(APP)

