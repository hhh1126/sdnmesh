default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

APP = json-c-0.12.1
APP_BASE = json-c

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn
export PKG_CONFIG_LIBDIR=$(SDN_BUILD_DIR)/lib
export PKG_CONFIG_PATH=$(SDN_BUILD_DIR)/lib/pkgconfig
export PKG_CONFIG_SYSROOT_DIR=$(SDN_BUILD_DIR)

.PHONY: default install $(APP_BASE) clean distclean

# $(SDN_BUILD_DIR) - where to install the dependency files(*.h/*.so) for other moudles
# $(INSTALL_DIR)   - where to install the target files(*.so/EXEC) for ROOT FS
install: $(APP_BASE)
	echo "$(CURR_DIR)/Makefile -->install staging"
	mkdir -p $(SDN_BUILD_DIR)/include/json-c
	mkdir -p $(SDN_BUILD_DIR)/lib
	cp -a $(APP)/*.h $(SDN_BUILD_DIR)/include/json-c
	cp -a $(APP)/.libs/libjson-c.so* $(SDN_BUILD_DIR)/lib/
	echo "$(CURR_DIR)/Makefile -->install target"
	mkdir -p $(INSTALL_DIR)/lib
	cp -a $(SDN_BUILD_DIR)/lib/libjson-c.so* $(INSTALL_DIR)/lib/
#Fix me!!! install json-c to json, just for libubox compile
	mkdir -p $(SDN_BUILD_DIR)/include/json
	cp -a $(APP)/*.h $(SDN_BUILD_DIR)/include/json

$(APP_BASE): info
	@if [ ! -e $(APP)/config.log ]; then \
	    echo "Untarring original $(APP) source"; \
	    tar zxf $(APP).tar.gz 2> /dev/null || true; \
	    echo "Building $(APP) to $(SDN_BUILD_DIR)/lib"; \
	    cd $(APP); \
	    ./configure \
			--enable-shared \
			--enable-static \
			ac_cv_func_malloc_0_nonnull=yes \
			ac_cv_func_realloc_0_nonnull=yes \
			--host=$(TOOLCHAIN_PREFIX) \
			--prefix=$(SDN_BUILD_DIR) \
			LDFLAGS="-L$(SDN_BUILD_DIR)/lib" \
			CFLAGS="-I$(SDN_BUILD_DIR)/include" || exit 1; \
	fi; \
	cd $(APP); \
	$(MAKE) -j1; \
	echo "Done building $(APP_BASE)"

clean:
	-make -C $(APP) clean
	echo "$(CURR_DIR)/Makefile -->clean staging"
	-rm -rf $(SDN_BUILD_DIR)/include/json-c
	-rm -f $(SDN_BUILD_DIR)/lib/libjson-c.so*
	echo "$(CURR_DIR)/Makefile -->clean target"
	-rm -f $(INSTALL_DIR)/lib/libjson-c.so*
	-rm -rf $(SDN_BUILD_DIR)/include/json

distclean: clean
	-rm -rf $(APP)

info:
	echo "$(CURR_DIR)/Makefile -->info"
	echo "INSTALL_DIR      $(INSTALL_DIR)"
	echo "SDN_BUILD_DIR    $(SDN_BUILD_DIR)"
