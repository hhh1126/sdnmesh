CC = $(CROSS)gcc
PWD = $(shell pwd)
TARGET ?= $(PWD)/target
ifneq ($(PLATFORM), openwrt)
ARCH ?= arc
endif

CFLAGS += -D_GNU_SOURCE
CFLAGS += -fPIC -pthread
CFLAGS += -g
ifneq ($(PLATFORM), openwrt)
	CFLAGS += -Werror -Wall
else
	CFLAGS += -Wno-unused-variable -Wimplicit-function-declaration -Wno-unused-parameter
endif
CFLAGS += -fno-strict-aliasing
ifeq ($(PLATFORM), pearl)
CFLAGS += -DPEARL_PLATFORM
endif
CFLAGS += -I./include
LDFLAGS += -L./lib

LDFLAGS += -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib
CFLAGS += -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include/libnl3

ifneq ($(TMP_STAGING_DIR),)
	LDFLAGS += -L$(TMP_STAGING_DIR)/lib -L$(TMP_STAGING_DIR)/usr/lib
	CFLAGS += -I$(TMP_STAGING_DIR)/include -I$(TMP_STAGING_DIR)/usr/include
endif

ifeq ($(ARCH), i386)
	CC += -m32
	LD += -m elf_i386
endif

CSMD_SRCS = csmd.c
CSMD_OBJS = $(CSMD_SRCS:.c=.o)
CSMD = csmd

CFG_EXAMPLE_SRCS = cfg_update_example.c
CFG_EXAMPLE_OBJS = $(CFG_EXAMPLE_SRCS:.c=.o)
CFG_EXAMPLE = cfg_update

LIB_DIR = lib
LIBCSM = $(LIB_DIR)/libcsm.so
LIBCSM_SRCS = csm_log.c csm_utils.c csm_plugin.c csm_core.c csm_helper.c csm_message.c csm_timer.c csm_test.c
LIBCSM_OBJS = $(LIBCSM_SRCS:.c=.o)

LIBCFG = $(LIB_DIR)/libcfg_ext.so
LIBCFG_SRCS = cfg_ext_qtn.c
LIBCFG_OBJS = $(LIBCFG_SRCS:.c=.o)

LIBCOMM = $(LIB_DIR)/libqsteer_comm_ext.so
LIBCOMM_SRCS = qsteer_comm_ext.c
LIBCOMM_OBJS = $(LIBCOMM_SRCS:.c=.o)

LOGIC_DIR = logic

LOGIC_SAMPLE1 = $(LOGIC_DIR)/libcsmlogicsample1.so
LOGIC_SAMPLE1_SRCS = logic_sample1.c
LOGIC_SAMPLE1_OBJS = $(LOGIC_SAMPLE1_SRCS:.c=.o)

SPDIA_DIR = spdia

COMM_DIR = comm

COMM_INACTIVE = $(COMM_DIR)/libcsmcomminactive.so
COMM_INACTIVE_SRCS = comm_inactive.c
COMM_INACTIVE_OBJS = $(COMM_INACTIVE_SRCS:.c=.o)

DRIVER_DIR = driver

DRIVER_QTN_NETLINK = $(DRIVER_DIR)/libcsmdriverqtnnl.so
DRIVER_QTN_NETLINK_SRCS = driver_qtn_netlink.c
DRIVER_QTN_NETLINK_OBJS = $(DRIVER_QTN_NETLINK_SRCS:.c=.o)

DRIVER_QTN_GENNL = $(DRIVER_DIR)/libcsmdriverqtngennl.so
DRIVER_QTN_GENNL_SRCS = driver_qtn_gennl.c
DRIVER_QTN_GENNL_OBJS = $(DRIVER_QTN_GENNL_SRCS:.c=.o)

ifeq ($(ARCH), arc)
DRIVER_QTN = $(DRIVER_QTN_GENNL)
endif
DRIVER_QTN += $(DRIVER_QTN_NETLINK)

ifeq ($(ARCH), $(filter $(ARCH), amd64 i386))
CFLAGS += -I/usr/include/libnl3
DRIVER_QTN += $(DRIVER_NL80211)
endif

RPECAT_DIR = rpecat

CSMD_CLI_SRCS = csmd_cli.c
CSMD_CLI_OBJS = $(CSMD_CLI_SRCS:.c=.o)
CSMD_CLI = csmd_cli

MISC_DIR = .
MISC_CSMD_CLI = $(MISC_DIR)/libcsmmisccsmdcli.so
MISC_CSMD_CLI_SRCS = misc_csmd_cli.c
MISC_CSMD_CLI_OBJS = $(MISC_CSMD_CLI_SRCS:.c=.o)

all: $(LIB_DIR) $(LIBCSM) $(LIBCFG) $(LIBCOMM) $(LOGIC_DIR) $(LOGIC_SAMPLE1) $(DRIVER_DIR) $(DRIVER_QTN) $(COMM_DIR) $(COMM_INACTIVE) qspdia $(CSMD) $(MISC_CSMD_CLI) $(CSMD_CLI)

$(CSMD_CLI): $(CSMD_CLI_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(MISC_CSMD_CLI): $(MISC_CSMD_CLI_OBJS)
	${CC} $(LDFLAGS) -shared -lcsm -lpthread -o $@ -lc $^

install: all qspdia_install config_install
	install -d $(TARGET)/usr/sbin
	install -d $(TARGET)/usr/lib/
	install -d $(TARGET)/usr/lib/misc
	install -m0755 $(CSMD) $(TARGET)/usr/sbin/
	install -m0755 $(CSMD_CLI) $(TARGET)/usr/sbin/
	cp -f $(MISC_CSMD_CLI) $(TARGET)/usr/lib/misc
	cp -rf $(LIB_DIR)/* $(TARGET)/usr/lib/
	cp -rf $(DRIVER_DIR) $(TARGET)/usr/lib/
	cp -rf $(LOGIC_DIR) $(TARGET)/usr/lib/
	cp -rf $(COMM_DIR) $(TARGET)/usr/lib/

config_install:
	install -d $(TARGET)/etc
	install -m0644 $(CSMD).json $(TARGET)/etc
	install -m0644 SPDIA_SONiQ.csmd.json $(TARGET)/etc
	install -m0644 SPDIA.csmd.json $(TARGET)/etc

install_staging: $(LIBCOMM) $(LIBCFG)
	cp cfg_ext.h $(STAGING_DIR)/include
	cp qsteer_comm_ext.h $(STAGING_DIR)/include
	cp include/* $(STAGING_DIR)/include
	cp $(LIBCOMM) $(STAGING_DIR)/usr/lib
	cp $(LIBCFG) $(STAGING_DIR)/usr/lib

$(LIB_DIR):
	-mkdir $@

$(LOGIC_DIR):
	-mkdir $@

$(DRIVER_DIR):
	-mkdir $@

$(COMM_DIR):
	-mkdir $@

%.o: %.c
	$(CC) $(CFLAGS) -pipe -c $<

$(CSMD): $(CSMD_OBJS) $(LIBCSM)
ifneq ($(PLATFORM), openwrt)
	$(CC) $(LDFLAGS) -o $@ $(CSMD_OBJS) -lcsm -ldl  -pthread -ljson -lm
else
	$(CC) $(LDFLAGS) -o $@ $(CSMD_OBJS) -lcsm -ldl  -pthread -ljson-c -lm
endif

$(CFG_EXAMPLE): $(CFG_EXAMPLE_OBJS) lib/libqsteer_comm_ext.so
	$(CC) $(LDFLAGS) -o $@ $(CFG_EXAMPLE_OBJS) -lqsteer_comm_ext

ifneq ($(PLATFORM), openwrt)
$(LOGIC_SAMPLE1): $(LOGIC_SAMPLE1_OBJS) $(LIBCSM)
else
$(LOGIC_SAMPLE1): $(LOGIC_SAMPLE1_OBJS)
endif
	${CC} $(LDFLAGS) -shared -lcsm -o $@ -lc $^

qspdia:
	ARCH=$(ARCH) CROSS=$(CROSS) make -C $(SPDIA_DIR)

qspdia_install: qspdia
	install -d $(TARGET)
	TARGET=$(TARGET) make -C $(SPDIA_DIR) install

qspdia_clean:
	make -C $(SPDIA_DIR) clean


ifneq ($(PLATFORM), openwrt)
$(COMM_INACTIVE): $(COMM_INACTIVE_OBJS) $(LIBCSM)
else
$(COMM_INACTIVE): $(COMM_INACTIVE_OBJS)
endif
	${CC} $(LDFLAGS) -shared -lcsm -o $@ -lc $^

$(LIBCOMM): $(LIBCOMM_OBJS)
	${CC} $(LDFLAGS) -shared -o $@ $^

$(LIBCFG): $(LIBCFG_OBJS)
	${CC} $(LDFLAGS) -shared -o $@ $^

$(LIBCSM): $(LIBCSM_OBJS)
	${CC} $(LDFLAGS) -shared -o $@ -lc -ldl $^


$(DRIVER_QTN_NETLINK): $(DRIVER_QTN_NETLINK_OBJS)
	${CC} -shared -o $@ $(LDFLAGS) -lc -pthread $^
$(DRIVER_QTN_GENNL): $(DRIVER_QTN_GENNL_OBJS)
	${CC} -shared -o $@ $(LDFLAGS) -lc -pthread -lnl-3 -lnl-genl-3 $^

rpecat_compile:
	 ARCH=$(ARCH) CROSS=$(CROSS) STAGING_DIR=$(STAGING_DIR) PLATFORM=$(PLATFORM) make -C $(RPECAT_DIR)

rpecat_install: rpecat_compile
	TARGET=$(TARGET) make -C $(RPECAT_DIR) install

rpecat_clean:
	make -C $(RPECAT_DIR) clean

utest_install:
	install -d $(TARGET)/tmp
	install -m0644  utest/cases/* $(TARGET)/tmp/

clean: qspdia_clean
	-rm -rf *.o $(CSMD) $(LIB_DIR) $(DRIVER_DIR) $(LOGIC_DIR) $(COMM_DIR) $(CSMD_CLI) $(MISC_CSMD_CLI)
