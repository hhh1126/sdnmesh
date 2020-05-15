default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

APP = libjson_7.6.1
APP_BASE = libjson

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn
export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default install $(APP) clean distclean

install: $(APP_BASE)
	echo "$(CURR_DIR)/Makefile -->install staging"
	mkdir -p $(SDN_BUILD_DIR)/include/json
	mkdir -p $(SDN_BUILD_DIR)/lib
	cp -a $(APP)/*.h $(SDN_BUILD_DIR)/include/json
	echo "$(CURR_DIR)/Makefile -->install target"
	#cp -a $(SDN_BUILD_DIR)/lib/$(APP).so* $(INSTALL_DIR)/lib/
	#$(STRIP) $(INSTALL_DIR)/lib/$(APP).so*

$(APP_BASE):
	cd $(APP); \
	$(MAKE) -j1; \
	echo "Done building $(APP)"

clean:
	-make -C $(APP) clean
	echo "$(CURR_DIR)/Makefile -->clean staging"
	-rm -rf $(SDN_BUILD_DIR)/include/json
	-rm -rf $(SDN_BUILD_DIR)/lib/libjson.so*
	echo "$(CURR_DIR)/Makefile -->clean target"
	-rm -f $(INSTALL_DIR)/lib/libjson.so*

distclean: clean
	-rm -rf $(APP)
