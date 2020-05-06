/*
 *  Copyright (c) 2018-2019, Semiconductor Components Industries, LLC
 *  ("ON Semiconductor")   f/k/a Quantenna. All rights reserved.
 *  This software and/or documentation is licensed by ON Semiconductor under
 *  limited terms and conditions.  The terms and conditions pertaining to the
 *  software and/or documentation are available at
 *  http://www.onsemi.com/site/pdf/ONSEMI_T&C.pdf ("ON Semiconductor Standard
 *  Terms and Conditions of Sale, Section 8 Software").  Reproduction and
 *  redistribution in binary form, without modification, for use solely in
 *  conjunction with a Quantenna chipset, is permitted with an executed
 *  Quantenna Software Licensing Agreement and in compliance with the terms
 *  therein and all applicable laws. Do not use this software and/or
 *  documentation unless you have carefully read and you agree to the limited
 *  terms and conditions.  By using this software and/or documentation, you
 *  agree to the limited terms and conditions.
 */

#ifndef __MAP_COMMON_H__
#define __MAP_COMMON_H__

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <libgen.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <linux/filter.h>
#ifndef Q_OPENWRT
#include <linux/if_ether.h>
#include <net/ethernet.h>
#else
#include <net/ethernet.h>
#include <linux/if_ether.h>
#endif
#include <netpacket/packet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/file.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <endian.h>
#include <byteswap.h>
#include <list.h>

#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include "libubus.h"

#define MAP_TRUE	(1)
#define MAP_FALSE	(0)

#define MAP_MACFMT		"[%02x:%02x:%02x:%02x:%02x:%02x]"
#define MAP_MACARG(_mac)	(_mac)[0], (_mac)[1], (_mac)[2], (_mac)[3], (_mac)[4], (_mac)[5]

#define MAP_MAC_EQ(_mac1, _mac2)			(0 == memcmp(_mac1, _mac2, ETH_ALEN))
#define MAP_MAC_COPY(_mac1, _mac2)			memcpy(_mac1, _mac2, ETH_ALEN)

#define MAP_MAC_NULL			"\x00\x00\x00\x00\x00\x00"
#define MAP_MAC_IS_NULL(_mac1)		(0 == memcmp(_mac1, MAP_MAC_NULL, ETH_ALEN))

#ifdef MEMORY_DEBUG
#define MAP_MALLOC(_s)		CSM_MALLOC(_s)
#define MAP_CALLOC(_n, _s)	CSM_CALLOC(_n, _s)

#define MAP_FREE(_p)		CSM_FREE(_p)
#else
#define MAP_CALLOC(_n, _s)	calloc(_n, _s)
#define MAP_MALLOC(_s)		malloc(_s)

#define MAP_FREE(_p)		free(_p)
#endif

#define MAP_ARRAY_SIZE(_a)		(sizeof(_a) / sizeof((_a)[0]))

#endif
