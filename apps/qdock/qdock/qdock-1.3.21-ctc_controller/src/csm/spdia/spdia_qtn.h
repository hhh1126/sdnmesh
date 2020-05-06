/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          		 **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef __SPDIA_QTN_H__
#define __SPDIA_QTN_H__

#include "spdia_common.h"
#include "qsteer.h"

/* Compatible for previous/existed spdia interface
 * little endianess for transport */
typedef struct spdia_head {
#define SPDIA_MAGIC_LEN		8
	uint8_t magic[SPDIA_MAGIC_LEN];
	uint32_t type;
	uint32_t size;			/* Size in bytes (including header) */
} __attribute__ ((packed)) spdia_head_t;

typedef struct spdia_info {
	spdia_head_t head;
	uint64_t timestamp;             /*!< Info collected releative time (ms) */
	uint8_t mac[ETH_ALEN];          /*!< Mac Address of station */
#ifdef PLATFORM_PEARL
#define SPDIA_CHAINS    8
#else
#define SPDIA_CHAINS	4
#endif
	int32_t rssis[SPDIA_CHAINS];    /*!< Per chain RSSI */
	int32_t hw_noise;               /*!< Receiver noise estimate(multipled by 10) */
	uint8_t bf_mode;                /*!< 11ac - 1, 11n - 0 */
	uint8_t nc;                     /*!< Number of columns in CSI matrix */
	uint8_t nr;                     /*!< Number of rows in CSI matrix */
	uint8_t bw;                     /*!< BW of current frame(0 - 20MHz, 1 - 40MHz, 2 - 80MHz) */
	uint8_t ng;                     /*!< Grouping parameter */
	uint8_t chan;                   /*!< Channel of current transmission */
	uint8_t mcs;                    /*!< MCS of current packet */
	uint8_t mcs_ss;                 /*!< Number of streams used for MCS */
	uint32_t ntones;                /*!< Number of subcarriers */
} __attribute__ ((packed)) spdia_info_t;

typedef struct spdia_cfg {
#ifdef SPDIA_SUPPORT_FILE_DUMP
#define SPDIA_DUMP_NONE		0
#define SPDIA_DUMP_BREF		1
#define SPDIA_DUMP_COMPACT	2
#define SPDIA_DUMP_DETAIL	3
	uint32_t dump_level;
	uint32_t dump_interval;
	uint32_t dump_burst;
	uint32_t dump_kbytes;
#endif

#ifdef SPDIA_SUPPORT_TCP_DUMP
	uint32_t dump_port;
#endif
} spdia_cfg_t;

typedef struct spdia_sta_cfg {
	struct list_head lh;
	uint8_t mac[ETH_ALEN];
	uint16_t period;
	uint8_t reorder;
	uint8_t ng;
	uint8_t smooth;
#define SPDIA_MODE_DATA_SHIFT	0
#define SPDIA_MODE_NDP_SHIFT	1
	uint8_t mode;
	uint8_t added;
} spdia_sta_cfg_t;

typedef struct spdia_ctx {
	void *ctx;
	int log_handle;

	int running;
	pthread_t thread;
	int ctrl_sock;

	spdia_cfg_t cfg;
	pthread_mutex_t sta_mutex;
	struct list_head sta_head;

#ifdef SPDIA_SUPPORT_TCP_DUMP
	pthread_mutex_t dump_mutex;
	int dump_server_sock;
	int dump_client_sock;
	struct sockaddr_in client_addr;
#endif
} spdia_ctx_t;

extern spdia_ctx_t g_ctx;

extern void spdia_load_cfg(void);
extern int spdia_update_diagnosed_sta(uint8_t *mac, uint16_t period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth);
extern void spdia_recv_ctrl_frame(spdia_ctx_t *spdia_ctx);

#if defined (SPDIA_SUPPORT_TCP_DUMP) || defined (SPDIA_SUPPORT_FILE_DUMP)
extern void spdia_init_dump_cfg(void);
extern int spdia_dump_init(void);
extern void spdia_dump_deinit(void);
extern void spdia_dump_info(spdia_info_t *info, uint8_t *csi, csmmsgh_t *h);
#endif
#ifdef SPDIA_SUPPORT_TCP_DUMP
extern void spdia_recv_dump_connect(void);
extern void spdia_recv_dump_client(void);
#endif

#define spdia_stadb_stah_ref(_stah)	do { if(_stah)	csm_get(_stah);} while(0)
#define spdia_stadb_stah_unref(_stah)	do { if(_stah)	csm_put(_stah);} while(0)

static inline int spdia_ctrl(void *ctx, uint8_t *mac, uint16_t period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth)
{
	return SONiQ_CSM_CSiQ_ctrl(ctx, mac, period, reorder,
		mode, ng, smooth);
}

static stah_t *spdia_find_stah(struct sta_sdb *db, uint8_t *mac)
{
	stah_t *stah;
	uint32_t hash = db->hash(mac);
	struct list_head *head;

	if(hash >= db->hash_size)
		return NULL;

	head = &db->stalh[hash];
	list_for_each_entry(stah, head, lh) {
		if (SPDIA_MAC_EQ(stah->mac, mac))
			return stah;
	}
	return NULL;
}

static inline bss_table_t *spdia_get_stadb_bss(void *ctx, uint8_t *mac)
{
	stah_t *stah = NULL;

	if (!mac)
		return NULL;

	struct sta_sdb *sdb = QSteer_CSM_getBSSTable(ctx);
	if (NULL == sdb)
		return NULL;

	stah = spdia_find_stah(sdb, mac);
	if (NULL != stah)
		spdia_stadb_stah_ref(stah);

	QSteer_CSM_putBSSTable(sdb);

	return (bss_table_t *)stah;
}

#endif

