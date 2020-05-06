/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          		 **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef __SPDIA_COMMON_H__
#define __SPDIA_COMMON_H__

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
#include <sys/stat.h>
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

#define SPDIA_MACFMT		"[%02x:%02x:%02x:%02x:%02x:%02x]"
#define SPDIA_MACARG(_mac)	(_mac)[0], (_mac)[1], (_mac)[2], (_mac)[3], (_mac)[4], (_mac)[5]

#define SPDIA_MAC_EQ(_mac1, _mac2)		(0 == memcmp(_mac1, _mac2, ETH_ALEN))
#define SPDIA_MAC_COPY(_mac1, _mac2)		memcpy(_mac1, _mac2, ETH_ALEN)

#ifdef MEMORY_DEBUG
#define SPDIA_MALLOC(_s)	CSM_MALLOC(_s)
#define SPDIA_CALLOC(_n, _s)	CSM_CALLOC(_n, _s)

#define SPDIA_FREE(_p)		CSM_FREE(_p)
#else
#define SPDIA_CALLOC(_n, _s)	calloc(_n, _s)
#define SPDIA_MALLOC(_s)	malloc(_s)

#define SPDIA_FREE(_p)		free(_p)
#endif

#endif

