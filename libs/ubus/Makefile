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

APP = ubus-5bae22e
APP_BASE = ubus

#export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
#export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
#export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default $(APP_BASE) clean distclean

# $(SDN_BUILD_DIR) - where to install the dependency files(*.h/*.so) for other moudles
# $(INSTALL_DIR)   - where to install the target files(*.so/EXEC) for ROOT FS
install: $(APP_BASE)
	echo "$(CURR_DIR)/Makefile -->install staging"
	mkdir -p $(SDN_BUILD_DIR)/include/ubus
	cp -a $(APP)/*.h   $(SDN_BUILD_DIR)/include/ubus
	cp -a $(APP)/libubus.so* $(SDN_BUILD_DIR)/lib/
	echo "$(CURR_DIR)/Makefile -->install target"
	mkdir -p $(INSTALL_DIR)/bin/
	mkdir -p $(INSTALL_DIR)/lib/
	cp -a $(APP)/libubus.so* $(INSTALL_DIR)/lib/
	install -m 755 $(APP)/ubus  $(INSTALL_DIR)/bin/
	install -m 755 $(APP)/ubusd $(INSTALL_DIR)/bin/

info:
	echo "$(CURR_DIR)/Makefile -->info"
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
			-DCMAKE_PREFIX_PATH=$(SDN_BUILD_DIR) \
			-DCMAKE_AR=$(AR) \
			-DCMAKE_LD=$(LD) \
			-DCMAKE_NM=$(NM) \
			-DCMAKE_RANLIB=$(RANLIB); \
	fi; \
		make -j1
	echo "Done building $(APP_BASE)"


clean:
	-make -C $(APP) clean
	echo "$(CURR_DIR)/Makefile -->clean staging"
	-rm -rf $(SDN_BUILD_DIR)/include/libubus
	-rm -f $(SDN_BUILD_DIR)/lib/libubus.so*
	echo "$(CURR_DIR)/Makefile -->clean target"
	-rm -f $(INSTALL_DIR)/lib/libubus.so*
	-rm -f $(INSTALL_DIR)/bin/ubus
	-rm -f $(INSTALL_DIR)/bin/ubusd


distclean: clean
	-rm -rf $(APP)

