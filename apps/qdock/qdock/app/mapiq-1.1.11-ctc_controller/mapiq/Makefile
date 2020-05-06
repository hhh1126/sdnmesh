CC = $(CROSS)gcc
ifeq ($(ARCH), i386)
	CC += -m32
endif
ifneq ($(PLATFORM), openwrt)
ARCH ?= arc
endif
CSM_DIR ?= ../csm
PWD = $(shell pwd)
TARGET ?= $(PWD)/target

CFLAGS += -I$(PWD) -I$(PWD)/../ -DLIST_H
CFLAGS += -I$(CSM_DIR)/include
CFLAGS += -fpic
CFLAGS += -g
ifneq ($(PLATFORM), openwrt)
CFLAGS += -Werror
CFLAGS += -Wall
else
CFLAGS += -Wno-unused-variable -Wimplicit-function-declaration -Wno-unused-parameter
REMOTE_RPC_DIR = ../../qcsapi-1.0/libs
endif
CFLAGS += -fno-strict-aliasing
CFLAGS += -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include
ifeq ($(ARCH), arc)
CFLAGS += -I$(SDK_DIR)/drivers/include/shared -I$(SDK_DIR)/include -I$(SDK_DIR)
QCSAPI_LIB = qcsapi
else
ifndef REMOTE_RPC_DIR
$(error $(ARCH) REMOTE_RPC_DIR needs to be specified when compiling MAPiQ at host side)
endif
CFLAGS += -I$(REMOTE_RPC_DIR)
CFLAGS += -DQTN_REMOTE_RPC_CALL
ifneq ($(PLATFORM), openwrt)
LDFLAGS += -L$(REMOTE_RPC_DIR)
else
LDFLAGS += -L$(REMOTE_RPC_DIR) -lrpc
endif
QCSAPI_LIB = qcsapi_client
endif

ifeq ($(ARCH), amd64)
        CFLAGS += -DARCH_IS_64BITS
endif
ifeq ($(MAPIQ_DEVID_FORMAT), string)
CFLAGS += -DMAPIQ_DEVID_STRING_FORMAT
endif

LDFLAGS += -pthread
LDFLAGS += -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib

MAPiQ_QTN = libmapqtn.so
MAPiQ_QTN_SRCS = map_qtn.c map_server.c map_extcfg.c map_qdock.c map_ctrl.c
MAPiQ_QTN_OBJS = $(MAPiQ_QTN_SRCS:.c=.o)

MAPiQ_QTN_EXTCFG = map_extcfg
ifeq ($(ARCH), arc)
MAPiQ_QTN_EXTCFG_SRCS = map_extcfg_qtn.c
else
MAPiQ_QTN_EXTCFG_SRCS = map_extcfg_qtn.c map_qtn_rpc.c
endif
MAPiQ_QTN_EXTCFG_OBJS = $(MAPiQ_QTN_EXTCFG_SRCS:.c=.o)

all: $(MAPiQ_QTN) $(MAPiQ_QTN_EXTCFG)

%.o: %.c
	$(CC) $(CFLAGS) -pipe -c $<

$(MAPiQ_QTN): $(MAPiQ_QTN_OBJS)
	${CC} $(LDFLAGS) -shared -o $@ -lc -lubox -lubus $^

$(MAPiQ_QTN_EXTCFG): $(MAPiQ_QTN_EXTCFG_OBJS)
ifneq ($(PLATFORM), openwrt)
	${CC} $(LDFLAGS) -o $@ $^ -lubox -lubus -lz -l${QCSAPI_LIB}
else
	${CC} $(LDFLAGS) -o $@ $^ -lubox -lubus -lz -l$(QCSAPI_LIB)
endif

install: all qmesh_install
	install -d $(TARGET)/usr/sbin
	install -d $(TARGET)/usr/lib/logic
	cp $(MAPiQ_QTN) $(TARGET)/usr/lib/logic
	cp $(MAPiQ_QTN_EXTCFG) $(TARGET)/usr/sbin
ifneq ($(PLATFORM), openwrt)
	install -D -m 755 start_map $(TARGET)/scripts/start_map
	install -D -m 755 start_mapagent $(TARGET)/scripts/start_mapagent
	install -D -m 755 start_mapcontroller $(TARGET)/scripts/start_mapcontroller
else
	install -D -m 755 start_map_npu $(TARGET)/scripts/start_map_npu
	install -D -m 755 start_mapagent $(TARGET)/scripts/start_mapagent_npu
	install -D -m 755 start_mapcontroller $(TARGET)/scripts/start_mapcontroller_npu
endif
	install -m0644 csmd.mapagent.json $(TARGET)/etc/

install_staging:
	-cp map_api.h $(STAGING_DIR)/usr/include

qmesh_install: install_staging
	-CROSS=$(CROSS) TARGET=$(TARGET) STAGING_DIR=$(STAGING_DIR) $(MAKE) -C qmesh install

qmesh_clean:
	-$(MAKE) -C qmesh clean

clean: qmesh_clean
	-rm -rf *.o
	-rm -f $(MAPiQ_QTN)
	-rm -f $(MAPiQ_QTN_EXTCFG)
	-rm -f $(TARGET)/usr/lib/logic/$(MAPiQ_QTN)
	-rm -f $(TARGET)/usr/sbin/$(MAPiQ_QTN_EXTCFG)

.PHONY:clean
