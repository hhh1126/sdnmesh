default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

APP_QDOCK = quantenna-qdock-1.3.21-ctc_controller
APP_MAPIQ = quantenna-qdock-mapiq-1.1.11-ctc_controller
APP_BASE = qdock

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn
#export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
#export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
#export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default install $(APP_BASE) clean distclean

install: $(APP_BASE)
	mkdir -p $(SDN_BUILD_DIR)/include/

$(APP_BASE):	
	@if [ ! -e $(APP_BASE)/config.log ]; then \
		echo "Untarring original $(APP_QDOCK) and $(APP_MAPIQ) source"; \
		tar zxf $(APP_QDOCK).tar.gz --strip-components=3 2> /dev/null || true; \
		tar zxf $(APP_MAPIQ).tar.gz --strip-components=3 2> /dev/null || true; \
		echo "Building $(APP_BASE) to $(SDN_BUILD_DIR)/lib"; \
		touch $(APP_BASE)/config.log; \
	fi
	$(MAKE) -C $(APP_BASE) all \
		ARCH=arm \
		TARGET_CROSS=$(CROSS_COMPILE) \
		TARGET_DIR=$(INSTALL_DIR) \
		STAGING_DIR=$(SDN_BUILD_DIR) \
		board_platform="ctcsdn"
	echo "Done building $(APP_BASE)"

clean:
	-make -C $(APP_BASE) clean
	-rm -f $(INSTALL_DIR)/lib/$(APP_BASE).so*

distclean: clean
	-rm -rf $(APP)
