default: install

CURR_DIR := $(shell pwd)
BUILD_DIR:=$(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR:=$(word 1, $(BUILD_DIR))

include $(BUILD_DIR)/make.common

APP_BASE = qdock

APP_MAPIQ_VER = 1.1.11-ctc_controller
APP_MAPIQ = quantenna-qdock-mapiq-$(APP_MAPIQ_VER)
QMESH_DIR = $(APP_BASE)/buildroot/package/qdock/app/mapiq-$(APP_MAPIQ_VER)/mapiq/qmesh

SDN_BUILD_DIR=$(BCM_FSBUILD_DIR)/sdn

.PHONY: default install $(APP_BASE) clean distclean

install: $(APP_BASE)
	mkdir -p $(INSTALL_DIR)/bin
	cp -a $(QMESH_DIR)/build/src/al_entity $(INSTALL_DIR)/bin


$(APP_BASE): info
	@if [ ! -e $(APP_BASE)/config.log ]; then \
		echo "original source $(APP_MAPIQ)"; \
		mkdir -p $(APP_BASE) ; \
		cp -a src/$(APP_MAPIQ_VER)/* ./$(APP_BASE)/ ; \
		echo $(APP_MAPIQ) > $(APP_BASE)/config.log; \
	fi

	$(MAKE) -C $(QMESH_DIR) install \
		ARCH=$(ARCH) \
		CROSS=$(CROSS_COMPILE) \
		TARGET=$(INSTALL_DIR) \
		STAGING_DIR=$(SDN_BUILD_DIR) \
	echo "Done building $(APP_BASE)"

clean:
	-make -C $(APP_BASE) clean
	-rm -rf $(APP_BASE)/config.log
	-rm -f $(INSTALL_DIR)/bin/al_entity

distclean: clean
	-rm -rf $(APP_BASE)

info:
	@echo "$(CURR_DIR)/Makefile -->info"
	@echo "INSTALL_DIR      $(INSTALL_DIR)"
	@echo "SDN_BUILD_DIR    $(SDN_BUILD_DIR)"
	@echo "APP_MAPIQ        $(APP_MAPIQ)"
	@echo "ARCH             $(ARCH)"
	@echo "CROSS_COMPILE    $(CROSS_COMPILE)"
