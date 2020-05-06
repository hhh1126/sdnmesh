QDOCK_VERSION=1.3
QDOCK_FULL_VERSION=1.3.21-ctc_controller

QDOCK_DIR=$(TOPDIR)/home/sdngw-bcm/BYZR_58/userspace/sdn/apps/qdock/qdock
QDOCK_SRC_DIR=$(QDOCK_DIR)/qdock-$(QDOCK_FULL_VERSION)/src
QDOCK_BIN_DIR=$(QDOCK_DIR)/qdock-$(QDOCK_FULL_VERSION)/bin
QDOCK_APP_DIR=$(QDOCK_DIR)/app


.PHONY: qdock qdock-clean
QTN_LICENSE_BRIEF:="Quantenna Proprietary"
QTN_LICENSE_FULL_PATH:="COPYING"
QTN_SOURCE_DOWNLOAD:="Provided as part of the SDK."
QTN_VERSION:=1.0.0
QTN_DESCRIPTION:="Quantenna QDock Framework"
QTN_INTERACTION:="A app framework for Quantenna"


all: 
	#install -D -m 755 $(QDOCK_DIR)/start_qdock $(TARGET_DIR)/usr/scripts/start_qdock
	$(MAKE) -C $(QDOCK_SRC_DIR) \
		CROSS=$(TARGET_CROSS) \
		TARGET="$(TARGET_DIR)" \
		PLATFORM="$(board_platform)" \
		STAGING_DIR=$(STAGING_DIR)
	$(MAKE) -C $(QDOCK_APP_DIR) \
		CROSS=$(TARGET_CROSS) \
		SDK_DIR="$(TOPDIR)/.." \
		TARGET="$(TARGET_DIR)" \
		PLATFORM="$(board_platform)" \
		STAGING_DIR=$(STAGING_DIR)

clean:
	-@if [ -d $(QDOCK_SRC_DIR) ];		\
	then						\
		$(MAKE) -C $(QDOCK_SRC_DIR) clean;	\
	fi
	$(MAKE) -C $(QDOCK_APP_DIR) clean

qdock-dirclean:

#############################################################
#
## Toplevel Makefile options
#
##############################################################
ifeq ($(strip $(BR2_PACKAGE_QDOCK)),y)
TARGETS+=qdock
endif
