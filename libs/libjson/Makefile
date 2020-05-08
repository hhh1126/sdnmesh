default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

APP = libjson
APP_BASE = libjson_7.6.1

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn
export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default install $(APP) clean distclean

install: $(APP)
	#cp -a $(SDN_BUILD_DIR)/lib/$(APP).so* $(INSTALL_DIR)/lib/
	#$(STRIP) $(INSTALL_DIR)/lib/$(APP).so*

$(APP):
	cd $(APP); \
	$(MAKE) -j1; \
	echo "Done building $(APP)"

clean:
	-make -C $(APP) clean
	-rm -f $(INSTALL_DIR)/lib/$(APP).so*

distclean: clean
	-rm -rf $(APP)