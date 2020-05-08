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

install: $(APP_BASE)
	mkdir -p $(SDN_BUILD_DIR)/include/json
	cp -a $(APP)/json.h $(SDN_BUILD_DIR)/include/json
	cp -a $(APP)/.libs/*.so* $(SDN_BUILD_DIR)/lib/
	cp -a $(APP)/.libs/*.a*  $(SDN_BUILD_DIR)/lib/
	cp -a $(SDN_BUILD_DIR)/lib/*.so* $(INSTALL_DIR)/lib/
	$(STRIP) $(INSTALL_DIR)/lib/*.so*

$(APP_BASE):
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
	-rm -f $(INSTALL_DIR)/lib/$(APP_BASE).so*

distclean: clean
	-rm -rf $(APP)

test:
	echo $(MAKE)
	echo $(CC)
