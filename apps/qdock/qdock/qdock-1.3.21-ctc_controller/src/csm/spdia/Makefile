CC = $(CROSS)gcc
ifeq ($(ARCH), i386)
	CC += -m32
endif
CSM_DIR ?= ../
PWD = $(shell pwd)
TARGET ?= $(PWD)/target

CFLAGS += -I$(PWD)
CFLAGS += -I$(CSM_DIR) -I$(CSM_DIR)/include
CFLAGS += -fpic
CFLAGS += -g
CFLAGS += -Werror
CFLAGS += -Wall
CFLAGS += -fno-strict-aliasing
LDFLAGS += -pthread

ifeq ($(PLATFORM), pearl)
CFLAGS += -DPLATFORM_PEARL
endif

SPDIA_QTN = libspdia_qtn.so
SPDIA_QTN_SRCS = spdia_qtn.c spdia_dump.c spdia_ctrl.c

SPDIA_QTN_OBJS = $(SPDIA_QTN_SRCS:.c=.o)

SPDIA_CLI = qspdia_cli
SPDIA_CLI_SRCS = spdia_cli.c
SPDIA_CLI_OBJS = $(SPDIA_CLI_SRCS:.c=.o)

CFLAGS += -DSPDIA_SUPPORT_FILE_DUMP -DSPDIA_SUPPORT_TCP_DUMP

all: $(SPDIA_QTN) $(SPDIA_CLI)

%.o: %.c
	$(CC) $(CFLAGS) -pipe -c $<

$(SPDIA_QTN): $(SPDIA_QTN_OBJS)
	${CC} $(LDFLAGS) -shared -o $@ -lc $^

$(SPDIA_CLI): $(SPDIA_CLI_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

install: all
	install -d $(TARGET)/usr/sbin
	install -d $(TARGET)/usr/lib/logic
	install -d $(TARGET)/scripts
	install -m0755 $(SPDIA_CLI) $(TARGET)/usr/sbin/
	install -m0755 start_spdia $(TARGET)/scripts/
	cp $(SPDIA_QTN) $(TARGET)/usr/lib/logic

clean:
	-rm -rf *.o
	-rm -f $(SPDIA_CLI)
	-rm -f $(SPDIA_QTN)
	-rm -f $(TARGET)/usr/lib/logic/$(SPDIA_QTN)
	-rm -f $(TARGET)/usr/sbin/$(SPDIA_CLI)

.PHONY:clean
