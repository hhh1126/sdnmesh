/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSM_UTILS_H_
#define _CSM_UTILS_H_

#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <dirent.h>
#include <endian.h>
#include <byteswap.h>
#include <syslog.h>
#include <linux/types.h>
#ifdef Q_OPENWRT
#include <pthread.h>
#else
#include <net/if.h>
#endif
#include "list.h"

//#define COLORFUL_WORLD

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define _STR(s)     #s
#define STR(s)      _STR(s)

/* ANSI color print */
#define COLOR_RED       31
#define COLOR_GREEN     32
#define COLOR_YELLOW    33
#define COLOR_BLUE      34
#define COLOR_PURPLE    35
#define COLOR_CYAN      36
#ifdef COLORFUL_WORLD
#define COLORFUL_STR(color, format)\
    "\33[1;" STR(color) "m" format "\33[0m"
#else
#define COLORFUL_STR(color, format)\
    format
#endif
#ifdef MEMORY_DEBUG
void *csm_debug_malloc(size_t size, char *file, int line);
void *csm_debug_calloc(size_t num, size_t size, char *file, int line);
void csm_debug_free(void *p, char *file, int line);
void *csm_debug_new(size_t size, char *file, int line);
void csm_debug_memory_dump(int type);
#define CSM_MALLOC(size) csm_debug_malloc((size), __FILE__, __LINE__)
#define CSM_CALLOC(num, size) csm_debug_calloc((num), (size), __FILE__, __LINE__)
#define CSM_FREE(ptr) csm_debug_free((ptr), __FILE__, __LINE__)
#define CSM_NEW(size)  csm_debug_new((size), __FILE__, __LINE__)
#else
#define CSM_NEW(size) csm_new((size))
#define CSM_MALLOC(size) malloc((size))
#define CSM_CALLOC(num, size) calloc((num), (size))
#define CSM_FREE(ptr) free((ptr))
#endif

#define CSM_FREE_AND_INIT(ptr)	do { if (ptr) {CSM_FREE(ptr); (ptr) = NULL; }} while(0)


#define INSERT_LIST(head, list) \
	do {\
		(list)->next = (head);\
		(head) = (list);\
	}while(0)

#define MACFMT "02x:%02x:%02x:%02x:%02x:%02x"
#define MACARG(sta) (sta)[0],(sta)[1],(sta)[2],(sta)[3],(sta)[4],(sta)[5]

#define BANDFMT "s"
#define BANDARG(band) ((band)==BAND_2G?"2.4G":((band)==BAND_5G?"5G":"Unknown"))

#define MDIDFMT "02x:%02x"
#define MDIDARG(mdid) (mdid)[0],(mdid)[1]

#define ETH_ALEN 6
#define MDID_LEN 2
#define HT_CAPABILITY_LEN 28
#define HT_OPERATION_LEN 24
#define VHT_CAPABILITY_LEN 14
#define VHT_OPERATION_LEN 7
#define PHY_TYPE_HT		7
#define PHY_TYPE_VHT		9
#define CSM_EVENT		0xFE
#define CSM_COMMAND		0xFF
#define REG_FRAME_MAXLEN 	128
#define PSK_KEYID_MAXLEN	32

#define MACADDR_EQ(_mac1, _mac2)			(0 == memcmp(_mac1, _mac2, ETH_ALEN))

/* AP reachabilitiy bits */
#define BTM_AP_REACH                0x03	/* b0, b1 bits */
/* Security */
#define BTM_SECURITY                0x04	/* b2 bit */
/* key scope */
#define BTM_KEY_SCOPE               0x08	/* b3 bit */


#define CSM_VER_1 1
#define CSM_VER_2 2
#define CSM_VER_3 3

#define CSM_CODING_FIXED 0
#define CSM_CODING_TLV 1

#define MATCH(field, value) (strcmp(field, value) == 0)

#define BIT(n) (1<<n)

#define SET_FLAG(value, flag) (value) |= (flag)
#define CLEAR_FLAG(value, flag) (value) &= (~(flag))
#define FLAG_IS_SET(value, flag) (((value) & (flag)) == (flag))

#define COPYMEM(dst, src, len) \
	do {\
		memcpy((dst), (src), (len));\
	}while(0)

#define COPYMDID(dst, src) COPYMEM(dst, src, MDID_LEN)
#define COPYMAC(dst, src) COPYMEM(dst, src, ETH_ALEN)
#define CLEARMAC(dst) memset((dst), 0, ETH_ALEN)
#define CLEARMDID(dst) memset((dst), 0, MDID_LEN)
#define MACEQUAL(dst,src) (!memcmp((dst), (src), ETH_ALEN))
#define MDIDEQUAL(dst,src) (!memcmp((dst), (src), MDID_LEN))
#define IS_ZERO_MAC(_mac)	(!((_mac)[0] | (_mac)[1] | (_mac)[2] | (_mac)[3] | (_mac)[4] | (_mac)[5]))

#define STA_IS_ASSOCIATED(sta) \
	(FLAG_IS_SET((sta)->flag, STATION_FLAG_ASSOCIATED))
#define IS_ASSOCIATED_WITH(sta, bss_mac) \
	(FLAG_IS_SET((sta)->flag, STATION_FLAG_ASSOCIATED) \
	&& (MACEQUAL((sta)->assoc_info.assoc_bssid, (bss_mac))))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le_to_host16(n) ((__u16) (__le16) (n))
#define host_to_le16(n) ((__le16) (__u16) (n))
#define be_to_host16(n) bswap_16((__u16) (be16) (n))
#define host_to_be16(n) ((__be16) bswap_16((n)))
#define le_to_host32(n) ((__u32) (__le32) (n))
#define host_to_le32(n) ((__le32) (__u32) (n))
#define be_to_host32(n) bswap_32((__u32) (__be32) (n))
#define host_to_be32(n) ((__be32) bswap_32((n)))
#define le_to_host64(n) ((__u64) (__le64) (n))
#define host_to_le64(n) ((__le64) (__u64) (n))
#define be_to_host64(n) bswap_64((__u64) (__be64) (n))
#define host_to_be64(n) ((__be64) bswap_64((n)))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#define le_to_host32(n) bswap_32(n)
#define host_to_le32(n) bswap_32(n)
#define be_to_host32(n) (n)
#define host_to_be32(n) (n)
#define le_to_host64(n) bswap_64(n)
#define host_to_le64(n) bswap_64(n)
#define be_to_host64(n) (n)
#define host_to_be64(n) (n)
#else
#error Could not determine CPU byte order
#endif

#define extract_host64(v) (le_to_host64(*(uint64_t*)(&(v))))
#define extract_host32(v) (le_to_host32(*(uint32_t*)(&(v))))
#define extract_host16(v) (le_to_host16(*(uint16_t*)(&(v))))

#ifndef NBBY
#define NBBY	(8)
/* Bit map related macros. */
#define setbit(a,i)     ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define clrbit(a,i)     ((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define isset(a,i)      ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define isclr(a,i)      (((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_a)		(sizeof(_a) / sizeof((_a)[0]))
#endif

typedef uint64_t timestamp_t;
typedef int32_t rssi_t;
typedef uint32_t phyrate_t;
typedef uint16_t bandwidth_t;

typedef pthread_mutex_t csm_lock_t;

void csm_log_init(void);
int csm_log_register(const char *name, int default_level);
void csm_log_printf(int handle, int level, const char *func, uint32_t line,
		    const char *fmt, ...);
void csm_log_dump(int handle, char *title, const char *func, uint32_t line,
		  uint8_t *buf, int len);
#if 1
int csm_log_settings_show(char *rep, int rep_len);
#else
void csm_log_settings_show(void);
#endif
int csm_level_no(const char *level_name);
int csm_log_set_level_by_handle(int handle, const char *level_name);
int csm_log_set_level(char *name, const char *level_name);
int csm_log_set_output(const char *output_name);
void csm_printf(int level, const char *fmt, ...);

extern int g_csm_log_handle;

#define CSM_ERROR(fmt, ...)	csm_log_printf(g_csm_log_handle, LOG_ERR, __func__, __LINE__, fmt "\n", ##__VA_ARGS__)
#define CSM_WARNING(fmt, ...)	csm_log_printf(g_csm_log_handle, LOG_WARNING, __func__, __LINE__, fmt "\n", ##__VA_ARGS__)
#define CSM_NOTICE(fmt, ...)	csm_log_printf(g_csm_log_handle, LOG_NOTICE, __func__, __LINE__, fmt "\n", ##__VA_ARGS__)
#define CSM_INFO(fmt, ...) 	csm_log_printf(g_csm_log_handle, LOG_INFO, __func__, __LINE__, fmt "\n", ##__VA_ARGS__)
#define CSM_DEBUG(fmt,...)	csm_log_printf(g_csm_log_handle, LOG_DEBUG, __func__, __LINE__, fmt "\n", ##__VA_ARGS__)
#define CSM_DUMP(_t, _d, _s)	csm_log_dump(g_csm_log_handle, _t, __func__, __LINE__, _d, _s)

#define CSM_SET_DEBUG_LEVEL(_l)	csm_log_set_level_by_handle(g_csm_log_handle, _l)

#define default_mdid (uint8_t *) "\x00\x00"
#define broadcast_ethaddr (uint8_t *) "\xff\xff\xff\xff\xff\xff"

#define STA_UPDATE_INFO_RXSS(sta, rxss) \
	do {\
		if ((rxss)>(sta)->sta_info.supported_rxss) {	\
			(sta)->sta_info.supported_rxss = (rxss);	\
		}\
	} while(0)

#define STA_UPDATE_RSSI_TS(sta, timestamp) \
	do {\
		if ((sta) && ((timestamp)>(sta)->last_rssi_ts))\
			(sta)->last_rssi_ts = (timestamp);\
	}while(0)
#define STA_UPDATE_BANDINFO_RXSS(sta, bandinfo, rxss) \
	do {\
		if ((rxss)>(bandinfo)->rx_ss) {\
			if ((bandinfo)->rx_ss) {\
				CSM_NOTICE(PPREFIX "Client[%" MACFMT "] overide rx ss from %d to %d", MACARG((sta)->h.mac),\
					(bandinfo)->rx_ss, (rxss));\
			}\
			(bandinfo)->rx_ss = (rxss);\
		}\
	} while(0)
#define STA_UPDATE_ASSOC_BSS(sta, newbssid, newmdid) \
	do {\
		if (STA_IS_ASSOCIATED((sta))) {\
			if (!MACEQUAL((newbssid), (sta)->assoc_info.assoc_bssid)) {\
				CSM_NOTICE(PPREFIX "Client[%" MACFMT "] association move from [%"\
					MACFMT "] to [%" MACFMT "].", MACARG((sta)->h.mac), MACARG((sta)->assoc_info.assoc_bssid), \
					MACARG((newbssid)));\
			}\
		} else {\
			CSM_INFO(PPREFIX "Client[%" MACFMT "] associate with [%" MACFMT "].", MACARG((sta)->h.mac), MACARG((newbssid)));\
		}\
		COPYMAC((sta)->assoc_info.assoc_bssid, (newbssid));\
		COPYMDID((sta)->assoc_info.assoc_mdid, (newmdid));\
		SET_FLAG((sta)->flag, (STATION_FLAG_ASSOCIATED|STATION_FLAG_AUTHED));\
		CLEAR_FLAG((sta)->flag, STATION_FLAG_LEGACY1_STA);\
	}while(0)

/* disassociate even bssid is not equal with record */
#define STA_UPDATE_DISASSOCIATATION(sta, oldbssid) \
	do {\
		if (STA_IS_ASSOCIATED((sta))) {\
			if ((oldbssid) && (!MACEQUAL((oldbssid), (sta)->assoc_info.assoc_bssid))) {\
				CSM_WARNING(PPREFIX "Client[%" MACFMT "] disassocated from [%" MACFMT "], but previous associated with [%" MACFMT "].",\
					MACARG((sta)->h.mac), MACARG(oldbssid), MACARG((sta)->assoc_info.assoc_bssid));\
			}\
			CLEARMAC((sta)->assoc_info.assoc_bssid);\
			CLEARMDID((sta)->assoc_info.assoc_mdid);\
			CLEAR_FLAG((sta)->flag, (STATION_FLAG_ASSOCIATED|STATION_FLAG_AUTHED));\
		} else {\
			CSM_WARNING(PPREFIX "Client[%" MACFMT "] disassocated, but it not associated with any BSS yet.",\
				MACARG((sta)->h.mac));\
		}\
	}while(0)

#define STA_UPDATE_DISASSOCIATATION_BSSID(sta, oldbssid) \
	do {\
		if (STA_IS_ASSOCIATED((sta))) {\
			if (!oldbssid)	{\
				CSM_WARNING(PPREFIX "Client[%" MACFMT "] disassocated from unknown bss, but previous associated with [%" MACFMT "].",\
					MACARG((sta)->h.mac), MACARG((sta)->assoc_info.assoc_bssid));\
			} else if (!MACEQUAL((oldbssid), (sta)->assoc_info.assoc_bssid)) {\
				CSM_WARNING(PPREFIX "Client[%" MACFMT "] disassocated from [%" MACFMT "], but previous associated with [%" MACFMT "].",\
					MACARG((sta)->h.mac), MACARG(oldbssid), MACARG((sta)->assoc_info.assoc_bssid));\
			} else {\
				CLEARMAC((sta)->assoc_info.assoc_bssid);\
				CLEARMDID((sta)->assoc_info.assoc_mdid);\
				CLEAR_FLAG((sta)->flag, (STATION_FLAG_ASSOCIATED|STATION_FLAG_AUTHED));\
			}\
		} else {\
			CSM_WARNING(PPREFIX "Client[%" MACFMT "] disassocated, but it not associated with any BSS yet.",\
				MACARG((sta)->h.mac));\
		}\
	}while(0)

#define STA_IS_BLACKLISTED(sta) \
	FLAG_IS_SET((sta)->flag,  STATION_FLAG_BLACKLISTED)
#define STA_BLACKLIST(sta) \
	do {\
		if (STA_IS_BLACKLISTED((sta))) {\
			CSM_NOTICE(PPREFIX "Client[%" MACFMT "] is already blacklisted.", MACARG((sta)->h.mac));\
		} else {\
			SET_FLAG((sta)->flag,  STATION_FLAG_BLACKLISTED);\
			CSM_INFO(PPREFIX "Blacklist Client[%" MACFMT "].", MACARG((sta)->h.mac));\
		}\
	}while(0)
#define STA_WHITELIST(sta) \
	do {\
		if (!STA_IS_BLACKLISTED((sta))) {\
			CSM_NOTICE(PPREFIX "Client[%" MACFMT "] is already whitelisted.", MACARG((sta)->h.mac));\
		} else {\
			CLEAR_FLAG((sta)->flag,  STATION_FLAG_BLACKLISTED);\
			CSM_INFO(PPREFIX "Whitelist Client[%" MACFMT "].", MACARG((sta)->h.mac));\
		}\
	}while(0)


#define BSS_IS_UP(bss) \
	(!FLAG_IS_SET((bss)->flag, BSS_FLAG_DOWN))

#define BSS_SET_UP(bss) \
	do {\
		CLEAR_FLAG((bss)->flag, BSS_FLAG_DOWN);\
	} while(0)

#define BSS_SET_DOWN(bss) \
	do {\
		SET_FLAG((bss)->flag, BSS_FLAG_DOWN);\
	} while(0)

enum csm_operating_band {
	BAND_2G = 0,
	BAND_5G,
	BAND_MAX
};

enum csm_mac_filter_mode {
	MAC_FILTER_DENY_MAC = 1,
	MAC_FILTER_ALLOW_MAC = 2,
};

enum csm_intf_status {
	RPE_INTF_STATE_INVALID = 0,
	RPE_INTF_STATE_DOWN = 1,
	RPE_INTF_STATE_UP = 2,
	RPE_INTF_STATE_DELETED = 3,
	RPE_INTF_STATE_NONAVAILABLE = 4,
	RPE_INTF_STATE_MAX,
};

enum csm_node_type {
	NODE_TYPE_UNKNOW = 0,
	NODE_TYPE_VAP = 1,
	NODE_TYPE_STA = 2,
	NODE_TYPE_WDS = 3,
	NODE_TYPE_TDLS = 4,
	NODE_TYPE_REPEATER = 5,
	NODE_TYPE_NOTWIFI = 6,
};

typedef void (*free_data_func) (void *);

typedef struct {
	uint32_t refcnt;
	csm_lock_t lock;
	free_data_func free_data;
	void *data;
} csmobj_t;

typedef struct {
	csmobj_t obj;
	int ready;
	void *csm;
	uint32_t type;
	void *init_param;
} csmpluginctx_t;

typedef struct {
	csmobj_t obj;
	char *msgbody;
} csmmsg_t;

static inline timestamp_t csm_get_timestamp(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static inline uint32_t csm_get_age(timestamp_t ts)
{
	timestamp_t now = csm_get_timestamp();
	return (uint32_t)((int64_t)now - (int64_t)ts);
}

static inline int32_t csm_get_timespan(timestamp_t a, timestamp_t b)
{
	return (int32_t)((int64_t)a - (int64_t)b);
}

static inline uint8_t csm_channel_to_band(uint8_t ch)
{
	return ((ch > 14) ? BAND_5G : BAND_2G);
}

#ifndef MIN
#define MIN(_a, _b)	(_a) > (_b) ? (_b) : (_a)
#endif

#ifndef MAX
#define MAX(_a, _b)	(_a) < (_b) ? (_b) : (_a)
#endif

#ifndef ABS
#define ABS(_x)	(((_x) > 0) ? (_x) : -(_x))
#endif

#endif
