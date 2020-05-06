/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSM_MESSAGE_H_
#define _CSM_MESSAGE_H_

#define csm_tlv_len(type) (csm_tlv_vlen(type)+sizeof(tlv_t))

#define CSM_IE_LEN(_l)	(((_l) + 3) & (~3))

#define CMD_GET_INTF_INFO_SPEC_GEN_CMD 1
#define CMD_GET_INTF_INFO_SPEC_FAT 3

#define CSM_RPE_VER(_n)		(_n)

#define CSM_RPE_MAX_LEN  1024
/* Management Frame Driver Process */
#define CSM_FLAG_SKB_COPY 	0
#define CSM_FLAG_BYPASS 	1

#define CSM_RPE_RCVBUF_SIZE	(240 * 1024)

enum csm_cmd_id {
	CMD_INIT			= 0x0001,
	CMD_DEINIT			= 0x0002,
	CMD_GET_INTF_STATUS		= 0x0003,
	CMD_GET_INTF_INFO		= 0x0004,
	CMD_DEAUTH			= 0x0005,
	CMD_STA_MAC_FILTER		= 0x0006,
	CMD_GET_STA_STATS		= 0x0007,
	CMD_BSS_TRANS_REQ		= 0x0008,
	CMD_START_FAT_MONITORING	= 0x0009,
	CMD_MONITOR_START		= 0x000A,
	CMD_MONITOR_STOP		= 0x000B,
	CMD_GET_NONASSOC_STATS		= 0x000C,
	CMD_FRAME			= 0x000D,
	CMD_REGISTER_FRAME		= 0x000E,
	CMD_SET_USER_CAP		= 0x000F,
	CMD_DISASSOC			= 0x0010,
	CMD_SET_CHAN			= 0x0011,
	CMD_ROAM			= 0x0012,
	CMD_SET_INTF_CFG		= 0x0013,

	CMD_SPDIA_CTRL = 0x0101,
};

enum csm_event_id {
	EVENT_INTF_STATUS		= 0x0001,
	EVENT_INTF_INFO			= 0x0002,
	EVENT_PROBE_REQ			= 0x0003,
	EVENT_CONNECT_COMPLETE		= 0x0004,
	EVENT_DEAUTH			= 0x0005,
	EVENT_DISASSOC			= 0x0006,
	EVENT_STA_PHY_STATS		= 0x0007,
	EVENT_BSS_TRANS_STATUS		= 0x0008,
	EVENT_NONASSOC_STA_PHY_STATS	= 0x0009,
	EVENT_AUTH			= 0x000A,
	EVENT_ASSOC			= 0x000B,
	EVENT_FRAME			= 0x000C,
	EVENT_RADIO_INFO		= 0x000D,
	EVENT_RADIO_STATUS		= 0x000E,
	EVENT_ROAM_FAIL			= 0x000F,
	EVENT_ASSOC_ADDITIONAL_INFO		= 0x0010,

	EVENT_SPDIA_INFO = 0x0101,
};

enum csm_message_tlv_type {
	TLVTYPE_IFNAME = 500,
	TLVTYPE_RADIO_NAME = 5500,
	TLVTYPE_MAC_MDID = 501,
	TLVTYPE_SEEN_BY_COMM = 5501,
	TLVTYPE_RADIO_MAC = 6501,
	TLVTYPE_BSSID = 7501,
	TLVTYPE_CHANNEL_BAND = 502,
	TLVTYPE_CHANNEL_BAND_CC = 5502,
	TLVTYPE_STA_MAC = 503,
	TLVTYPE_STA_INFO_COMM = 5503,
	TLVTYPE_RX_PHYRATE = 504,
	TLVTYPE_TX_PHYRATE = 505,
	TLVTYPE_RX_PHYRATE_BW = 5504,
	TLVTYPE_SUPPORTED_PHYRATE_COMM = 5505, /* conflict with TLVTYPE_TX_PHYRATE_BW */
	TLVTYPE_TS_LAST_RX = 506,
	TLVTYPE_AGE_LAST_RX = 5506,
	TLVTYPE_TS_LAST_TX = 507,
	TLVTYPE_AGE_LAST_TX = 5507,
	TLVTYPE_AVERAGE_FAT = 508,
	TLVTYPE_AVG_FAT_COMM = 5508,
	TLVTYPE_INTERFACE_CAPABILITY = 509,
	TLVTYPE_INTERFACE_FEAT_COMM = 5509,
	TLVTYPE_RSSI = 510,
	TLVTYPE_RSSI_ADV = 5510,
	TLVTYPE_PSK_KEYID = 5511,
	TLVTYPE_ROAM_FAIL = 551,
	TLVTYPE_SSID = 511,
	TLVTYPE_AVG_STA_AIRTIME = 512,
	TLVTYPE_TX_PHYRATE_COMM = 512,
	TLVTYPE_RX_PHYRATE_COMM = 5512,
	TLVTYPE_BEACON_INTERVAL = 518,
	TLVTYPE_STA_RSSI_COMM = 519,
	TLVTYPE_PKT_CNT = 520,
	TLVTYPE_PKT_CNT_HIST = 5520,
	TLVTYPE_BSS_STATUS_COMM = 521,
	TLVTYPE_NODE_TYPE = 522,
	TLVTYPE_FRAME = 523,
	TLVTYPE_FRAME_RX_SEL = 524,
	TLVTYPE_FRAME_TX_SEL = 5524,
	TLVTYPE_BACKBONE_INFO = 525,
	TLVTYPE_BL_MASK = 526,
	TLVTYPE_ADDIES = 5526,
	TLVTYPE_STATUS_CODE = 527,
	TLVTYPE_NRIE_INDEX = 528,
	TLVTYPE_EXT_INTF_CAPABILITY = 529,
	TLVTYPE_EXTCAP_SETS = 532,
	TLVTYPE_THIRD_CC = 534,
	TLVTYPE_REG_MGMT_FRAME_RX = 536,
	TLVTYPE_REG_MGMT_FRAME_TX = 5536,
	TLVTYPE_IE_EDIT_ALLOWED = 537,
	TLVTYPE_EXTCAP_EDIT_ALLOWED = 538,
	TLVTYPE_REFERENCE = 540,
	TLVTYPE_TX_POWER_BACKOFF = 543,
	TLVTYPE_MAX_BSSES = 544,
	TLVTYPE_OPCLASS_INFO = 545,
	TLVTYPE_OPCLASS = 5545,
	TLVTYPE_NONOP_CHANS = 546,
	TLVTYPE_MIN_FREQ_SEPS = 547,
	TLVTYPE_PREFERENCES = 5547,
	TLVTYPE_CH_CHANGE_INFO = 548,
	TLVTYPE_LINK_STATS = 549,
	TLVTYPE_ESPI = 550,
	TLVTYPE_RADIO_STATE = 552,
	TLVTYPE_INTF_FEATS = 553,
	TLVTYPE_MONITOR_CFG = 554,
	TLVTYPE_OMONITOR_CFG = 555,
	TLVTYPE_INTERWORKINGPROBES_CFG = 572,
	TLVTYPE_IES_COMM = 560,
	TLVTYPE_HT_CAPABILITY = 45,
	TLVTYPE_HT_OPERATION = 61,
	TLVTYPE_VHT_CAPABILITY = 191,
	TLVTYPE_VHT_OPERATION = 192,
	TLVTYPE_HE_CAPABILITY	= ((255 << 8) + 35),
	TLVTYPE_HE_OPERATION	= ((255 << 8) + 36),

	TLVTYPE_RSSI_VECTOR = 601,
	TLVTYPE_NOISE = 602,
	TLVTYPE_SPDIA_CONF = 603,
	TLVTYPE_SPDIA_TONES = 604,
	TLVTYPE_SPDIA_DETAILS = 605,
	TLVTYPE_SPDIA_PAYLOAD = 606,
	TLVTYPE_SPDIA_SUPPORTED_FEATURES = 607,
	TLVTYPE_SPDIA_CAPABILITIES = 608,
	TLVTYPE_SPDIA_DATA_INDEX = 609,
};

enum deauth_code {
	DEAUTH_CODE_INVALID = 0,
	DEAUTH_CODE_BSS_TRANS = 12,
	DEAUTH_CODE_LACK_BANDWIDTH = 33,
};

typedef struct {
	uint16_t type;
	uint16_t len;
	uint8_t value[0];
} __attribute__ ((packed)) tlv_t;

typedef struct {
	uint16_t id;
	uint8_t coding;
	uint8_t api_ver;
	uint8_t bssid[ETH_ALEN];
	uint16_t payload_len;
	uint8_t payload[0];
} __attribute__ ((packed)) csmmsgh_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t reason_code;
	uint8_t direction;
} __attribute__ ((packed)) evt_deauth_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t status_code;
} __attribute__ ((packed)) evt_bss_trans_status_t;


typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t reason_code;
	uint8_t direction;
} __attribute__ ((packed)) evt_disassoc_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t curr_band;
	int32_t rssi;
	uint16_t rx_ss;
	uint16_t max_phyrate;
	timestamp_t tstamp;
	uint8_t channel;
	uint8_t capability;
	uint16_t cookie_len;
	uint8_t cookie[0];
} __attribute__ ((packed)) evt_probe_req_t;

#define evt_assoc_t	evt_probe_req_t

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint8_t curr_band;
	uint8_t channel;
	int32_t rssi;
	uint64_t tstamp;
	uint16_t reserved1;
	uint16_t cookie_len;
	uint8_t cookie[0];
} __attribute__ ((packed)) evt_auth_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t rx_ss;
	uint16_t max_phyrate;
	union {
		struct {
			uint8_t node_type;
			uint8_t curr_band_v4;
		};
		uint16_t curr_band;
	} node_bype_band;
	uint8_t channel;
	uint8_t capability;
	uint16_t cookie_len;
	uint8_t cookie[0];
} __attribute__ ((packed)) evt_connect_complete_t;

typedef struct {
	csmmsgh_t h;
	uint8_t ifname_size;
	char ifname[19];
	uint32_t status;
} __attribute__ ((packed)) evt_intf_status_t;

typedef struct {
	csmmsgh_t h;
} __attribute__ ((packed)) cmd_init_t;

typedef struct _cmd_deinit_t {
	csmmsgh_t h;
} __attribute__ ((packed)) cmd_deinit_t;

typedef struct {
	csmmsgh_t h;
	uint8_t ifname_size;
	char ifname[19];
} __attribute__ ((packed)) cmd_get_intf_status_t;

typedef struct {
	csmmsgh_t h;
	uint8_t ifname_size;
	char ifname[19];
	uint32_t specifier;
} __attribute__ ((packed)) cmd_get_intf_info_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t reasoncode;
} __attribute__ ((packed)) cmd_deauth_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t allow_mac;
} __attribute__ ((packed)) cmd_mac_filter_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
} __attribute__ ((packed)) cmd_get_sta_stats_t;

/* to be defined */
typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
	uint16_t timer;
	uint8_t mode;
	uint8_t validity;
	uint8_t bssid[ETH_ALEN];
	uint32_t bssid_info;
	uint8_t opclass;
	uint8_t channel;
	uint8_t phytype;
	uint8_t subel_len;
	uint8_t subels[0];
} __attribute__ ((packed)) cmd_bss_trans_req_t;

typedef struct _cmd_start_fat_monitoring_t {
	csmmsgh_t h;
	uint8_t ifname_size;
	char ifname[19];
	uint32_t fat_period;
} __attribute__ ((packed)) cmd_start_fat_monitoring_t;

typedef struct {
	csmmsgh_t h;
	uint8_t ifname_size;
	char ifname[19];
	uint16_t peroid;
	uint16_t duty_cycle;
} __attribute__ ((packed)) cmd_monitor_start_t;

typedef struct {
	csmmsgh_t h;
	uint8_t ifname_size;
	char ifname[19];
} __attribute__ ((packed)) cmd_monitor_stop_t;

#define CSM_SPDIA_REORDER_SHIFT		0
#define CSM_SPDIA_MODE_SHIFT		1
#define CSM_REORDER_MASK		0x01
#define CSM_OPERATION_MODE_MASK		0x03

typedef struct {
	csmmsgh_t h;
	uint8_t sta[ETH_ALEN];
	uint16_t period;
	uint8_t	spdia_feature;
	uint8_t spdia_ng;
	uint8_t spdia_smooth;
	uint8_t reserved;
} __attribute__((packed)) cmd_spdia_config_ctrl_t;

typedef struct {
	csmmsgh_t h;
	uint8_t sta_mac[ETH_ALEN];
} __attribute__ ((packed)) cmd_get_nonassoc_stats_t;

typedef struct sta_info {
	uint8_t mac[ETH_ALEN];
	uint8_t capability;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t rx_ss:3;
	uint8_t reserved:2;
	uint8_t band_2g:1;
	uint8_t band_5g:1;
	uint8_t associated:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t associated:1;
	uint8_t band_5g:1;
	uint8_t band_2g:1;
	uint8_t reserved:2;
	uint8_t rx_ss:3;
#endif
} __attribute__ ((packed)) sta_info_t;

/* AddIE FrameMask in 5526 */
#define RPE_APPIE_FOR_PROBE	(0x0100)
#define RPE_APPIE_FOR_ASSOC	(0x0200)
#define RPE_APPIE_FOR_AUTH	(0x0400)
#define RPE_APPIE_FOR_BEACON	(0x0800)

typedef struct {
	uint8_t *mac;
	uint8_t *assoc_bss;
	uint8_t *seenby_bss;
	uint8_t *rx_phyrate;
	uint8_t *tx_phyrate;
	uint8_t *ts_last_rx;
	uint8_t *age_last_rx;
	uint8_t *ts_last_tx;
	uint8_t *age_last_tx;
	uint8_t *pkts_per_sec;
	uint8_t *avg_airtime;
	uint8_t *rssi;
	uint8_t *adv_rssi;
} sta_parse_stats_t;
typedef void (*process_sta_func_t)(csmctx_t *, bss_table_t *, sta_parse_stats_t *);

typedef int (*csm_event_func_t) (csmctx_t *, csmmsgh_t *, bss_table_t *,
				 drvctx_t *);
typedef int (*csm_cmd_func_t) (csmctx_t *, csmmsgh_t *, bss_table_t *,
			       drvctx_t *);
typedef struct _csm_event_handler {
	int16_t id;
	const char *name;
	csm_event_func_t efunc;
	uint32_t cnt;
} csm_event_handler;

typedef struct _csm_cmd_handler {
	int16_t id;
	const char *name;
	csm_cmd_func_t efunc;
	uint32_t cnt;
} csm_cmd_handler;

csm_event_handler *csm_get_event_handler(int16_t id);

csm_cmd_handler *csm_get_cmd_handler(int16_t id);
csmmsgh_t *csm_get_msg_body(csmmsg_t * csmmsg);
int16_t csm_tlv_vlen(uint16_t type);
uint32_t csm_encap_tlv(uint8_t * start, uint16_t type, void *value,
		  uint16_t value_len);
static inline uint32_t csm_encap_tlv_uint16(uint8_t *pos, uint16_t type, uint16_t value)
{
	value = host_to_le16(value);
	return csm_encap_tlv(pos, type, (void *)(&value), sizeof(value));
}

static inline uint32_t csm_encap_tlv_uint32(uint8_t *pos, uint16_t type, uint32_t value)
{
	value = host_to_le32(value);
	return csm_encap_tlv(pos, type, (void *)(&value), sizeof(value));
}

static inline uint32_t csm_encap_tlv_uint64(uint8_t *pos, uint16_t type, uint64_t value)
{
	value = host_to_le64(value);
	return csm_encap_tlv(pos, type, (void *)(&value), sizeof(value));
}

#define CSM_RPE_IE_GET_VALUE(_frm)         (((tlv_t *)(_frm))->value)
#define CSM_RPE_IE_GET_LEN(_frm)           (le_to_host16(((tlv_t *)(_frm))->len))


extern int csm_decode_bss_tlv(csmctx_t * csm, bss_table_t * bss, uint8_t *device_id,
			      csmmsgh_t * h, csmpluginctx_t * ctx);
extern int csm_decode_station_tlv(csmctx_t * csm, bss_table_t * bss,
				  csmmsgh_t * h);
extern void csm_process_intf_status(csmctx_t *csm, bss_table_t *bss, uint32_t status);
extern void csm_reset_assoc_info(sta_table_t *sta);
#endif
