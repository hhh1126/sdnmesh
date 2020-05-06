/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSM_CORE_H_
#define _CSM_CORE_H_
#ifdef Q_OPENWRT
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#define HASH_SIZE_256 256
#define HASH_SIZE_16 16
#define AVERAGER_SHIFT 3

//#define LOCKDEBUG

#define CSM_LOCK_INIT(data) do {pthread_mutex_init(&((data)->lock), NULL);}while (0)
#ifdef LOCKDEBUG
#define CSM_LOCK(data) do {\
		printf("lock %p, %s:%d\n", (data), __FILE__, __LINE__);\
		pthread_mutex_lock(&(((csmobj_t *)data)->lock));\
	}while(0)
#define CSM_UNLOCK(data) do {\
		printf("unlock %p, %s:%d\n", (data), __FILE__, __LINE__);\
		pthread_mutex_unlock(&(((csmobj_t *)data)->lock));\
	}while(0)
#else
#define CSM_LOCK(data) pthread_mutex_lock(&(((csmobj_t *)data)->lock))
#define CSM_UNLOCK(data) pthread_mutex_unlock(&(((csmobj_t *)data)->lock))
#endif
#define CSM_TOUCH(data) do {(data)->age++; if ((data)->age==0) (data)->age++;}while(0)

#define CSM_REPLACE_OBJ(orig, new) \
	do {\
		if ((orig))\
			csm_put((orig));\
		(orig) = (new);\
	}while(0)

#define GET_CSMCTX(handle) (((csmpluginctx_t *)((handle)))->csm)
#define GET_CSMINITPARAM(handle) (((csmpluginctx_t *)((handle)))->init_param)

typedef uint32_t(*hash_func_t) (uint8_t *);
typedef void (*csm_timer_func_t) (void *, void *);

typedef struct {
	csm_lock_t lock;
	pthread_cond_t wait;
	int running;
	struct list_head tlist;
	pthread_t thread;
} csmtimerctx_t;

typedef struct {
	timestamp_t age_timeout;
} sta_table_ageout_config_t;

typedef struct {
	uint16_t phyrate_avg_age;
	uint16_t rssi_avg_age;
	uint32_t statsdump_lines_perfile;
	uint8_t statsdump_files;
} csm_param_t;

typedef struct {
	uint8_t ind;
	uint32_t lines;
	FILE *file;
} csm_stats_dump_t;

typedef struct {
	csm_lock_t lock;
	void *logic_plugins;
	void *drv_plugins;
	void *comm_plugins;
	void *misc_plugins;
	/* mobility domain(s) */
	void *mds;
	/* database for radio(s) */
	void *radio_db;
	/* database for bss(s) */
	void *bss_db;
	/* database for station(s) */
	void *station_db;
	void *bss_db_snapshot;
	void *station_db_snapshot;
	void *drvs;
	void *comms;
	void *miscs;
	csmtimerctx_t timerctx;
	sta_table_ageout_config_t sta_ageout_config;
	csm_param_t params;
	csm_stats_dump_t stats_dump;
	void *devid_db;
	void *mdid_db;
} csmctx_t;

typedef struct mobility_domain {
	csmpluginctx_t pluginctx;
	uint8_t mdid[MDID_LEN];
	struct plugin_instance logic[LOGIC_ROLE_MAX];
	uint32_t instance_mask;
	struct mobility_domain *next;
} mobility_domain_t;

typedef struct drvctx {
	csmpluginctx_t pluginctx;
	struct plugin_instance drv;
	struct drvctx *next;
} drvctx_t;

typedef struct commctx {
	csmpluginctx_t pluginctx;
	struct plugin_instance comm;
	struct commctx *next;
} commctx_t;

typedef struct miscctx {
	csmpluginctx_t pluginctx;
	struct plugin_instance misc;
	struct miscctx *next;
} miscctx_t;

typedef struct _stah_t {
	csmobj_t obj;
	uint32_t age;
	struct list_head lh;
	uint8_t mac[ETH_ALEN];
} stah_t;

struct sta_sdb;

typedef int (*sta_signal_func_t) (stah_t *, void *ctx, void *param);
typedef void (*sta_signal_release_func_t) (void *ctx, void *param);
typedef void (*sta_early_init_func) (stah_t *, void *data1, void *data2);

typedef void (*sta_copy_func_t) (struct sta_sdb *, stah_t *, stah_t *);
typedef uint32_t(*sta_ageout_func_t) (stah_t *, stah_t **, void *);
typedef int (*stadb_sta_delete_func_t) (struct sta_sdb *, stah_t *);

enum {
	STA_SIGNAL_ON_CREATE = 0,
	STA_SIGNAL_ON_DESTROY,
	STA_SIGNAL_MAX,
};

typedef struct {
	struct list_head lh;
	sta_signal_func_t func;
	void *ctx;
	void *param;
	sta_signal_release_func_t cb;
} sta_signal_handler_t;

struct sta_sdb {
	csmobj_t obj;
	sta_copy_func_t sta_copy;
	struct list_head sta_signal_handler_lh[STA_SIGNAL_MAX];
	int32_t sta_size;
	hash_func_t hash;
	sta_ageout_func_t ageout;
	stadb_sta_delete_func_t db_delete_sta;
	void *ageout_data;
	int32_t hash_size;
	int32_t size;
	int32_t max_size;
	struct list_head stalh[0];
};

enum _sta_capab {
	STA_CAPAB_HT_BW_SUPPORT = BIT(0),
	STA_CAPAB_160M = BIT(1),
	STA_CAPAB_160M_80P80 = BIT(2),
	STA_CAPAB_BSS_TRANS_SUPPORT = BIT(3),
	STA_CAPAB_VHT_SUPPORT = BIT(4),
	STA_CAPAB_MU_BEAMFORMER = BIT(5),
	STA_CAPAB_MU_BEAMFORMEE = BIT(6),
};

typedef union {
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t ht_bw:1;
		uint8_t vht_bw:2;
		uint8_t bss_transition_supported:1;
		uint8_t vht_supported:1;
		uint8_t mu_beamformer_supported:1;
		uint8_t mu_beamformee_supported:1;
		uint8_t ht_supported:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint8_t ht_supported:1;
		uint8_t mu_beamformee_supported:1;
		uint8_t mu_beamformer_supported:1;
		uint8_t vht_supported:1;
		uint8_t bss_transition_supported:1;
		uint8_t vht_bw:2;
		uint8_t ht_bw:1;
#endif
	};
	uint8_t cap;
} sta_cap_t;

typedef enum {
	BACKBONE_TYPE_NONE = 0,
	BACKBONE_TYPE_INDEPENDENT,
	BACKBONE_TYPE_SHARED,
} backbone_type_e;

typedef struct {
	backbone_type_e backbone_type;
	uint8_t uplink_local[ETH_ALEN];
	uint16_t fixed_phyrate;
} backbone_info_t;

typedef struct {
	stah_t h;
	struct list_head bss_lh;
} devid_table_t;

typedef struct {
	uint8_t chan;

	uint8_t static_nonoperable;
#define CSM_CHAN_REASON_UNAVAILABLE			0x00
#define CSM_CHAN_REASON_UNAVAILABLE_CAC_TODO		0x0A
#define CSM_CHAN_REASON_UNAVAILABLE_RADAR_DETECTED	0x07
#define CSM_CHAN_REASON_AVAILABLE			0x0F
#define CSM_CHAN_REASON_AVAILABLE_CAC_COMPLETED		0x09
	uint8_t reason;
#define CSM_CHAN_MAX_PREF	0x0F
	uint8_t preference;
	uint8_t min_freq_separation;        /*!< Minimum frequency separation (in multiples of 10 MHz) that this radio would require when operating on this channel */
} chan_entry_t;

typedef struct {
	uint8_t global_opclass;					/*!< Global operation class id */
	uint8_t bandwidth;
	uint8_t max_txpower;					/*!< Max tx power */
#define CSM_CHAN_MAXNUM_PER_OPCLASS	32
	uint8_t chan_nums;
	chan_entry_t chans[CSM_CHAN_MAXNUM_PER_OPCLASS];	/*!< channels belongs to this operation class */
} opclass_entry_t;

typedef struct {
	stah_t h;
	char ifname[IFNAMSIZ + 1];

#define IFTYPE_1905_11B		0x0100
#define IFTYPE_1905_11G		0x0101
#define IFTYPE_1905_11A		0x0102
#define IFTYPE_1905_11N_2G	0x0103
#define IFTYPE_1905_11N_5G	0x0104
#define IFTYPE_1905_11AC_5G	0x0105
#define IFTYPE_1905_11AX	0x0108
	uint16_t iftype_1905;

#define CSM_RADIO_POWER_SAVE	(1 << 0)
	uint8_t powerState;
	uint8_t maxVAPs;
	uint8_t opclass;
	uint8_t chan;
	uint16_t fat;
	uint8_t tx_power_backoff;
	timestamp_t latest_fat_ts;

#define CSM_OPCLASS_MAXNUM	32
	uint8_t opclass_nums;
	opclass_entry_t opclasses[CSM_OPCLASS_MAXNUM];      /*!< Operation Classes supported on this radio */

	struct list_head bss_head;
} radio_table_t;

#define CSM_MAKE_PSEUDO_MAC(_mac, _mdid)	do {	\
	memset((_mac), 0, ETH_ALEN);	\
	memcpy((_mac) + 4, (_mdid), MDID_LEN);	} while (0)
#define CSM_MDID_FROM_PSEUDO_MAC(_mac)	((_mac) + 4)
typedef struct {
	/* first 2 bytes in MAC as MDID */
	stah_t h;
	uint8_t hessid[ETH_ALEN];
	/* internal used to avoid dead lock */
	struct list_head lh;
} mdid_table_t;

typedef struct {
	struct list_head lh;
	uint8_t subtype;
	uint8_t match_len;
	uint8_t match[0];
} frame_match_t;

#define SUPP_EID_MASK_BYTES	((256 + (NBBY - 1)) / NBBY)
#define SUPP_EXTCAP_MASK_BYTES	12
typedef struct {
	struct list_head lh;
	uint8_t mac[ETH_ALEN];
} spdia_sta_t;

typedef struct {
	uint8_t valid;		/*!< Valid */
	uint8_t format;		/*!< Data Format (see Table 9-261 of Ref. IEEE802.11-2016) */
	uint8_t window;		/*!< BA Window Size (see Table 9-262 of Ref. IEEE802.11-2016) */
	uint8_t duration;	/*!< Data PPDU Duration target (see  §9.4.2.174 of Ref. IEEE802.11-2016) */
} espi_t;

typedef struct {
	/* with embedded bssid */
	stah_t h;
	enum csm_node_type iftype;
	uint8_t bssid[ETH_ALEN];
	uint8_t dev_id[ETH_ALEN];
	struct list_head lh;	/* for link co-located bss */
	radio_table_t *radio;
	struct list_head radio_lh;	/* for link bss created on same radio */
	uint8_t mdid[MDID_LEN];
	backbone_info_t backbone_info;
	uint8_t band;
	uint16_t binterval;	/* ms */
	uint16_t fat;
	uint32_t stats_event_period; /* seconds */
	timestamp_t last_fat;
	uint8_t tx_power_backoff;
	/* capabilities information field extract from beacon,
	 * probe/assoc/request */
	uint8_t capabilities_infomation[2];
	/* BSS capability bitmask as
	   enum RPE_intf_bss_capab {
	   Qsteer_CAPAB_SUPPORTS_BSS_TRANS=0x1
	   Qsteer_CAPAB_IS_HT = 0x2
	   Qsteer_CAPAB_IS_VHT = 0x4
	   }; */
	sta_cap_t bss_capability;
#define CSM_DRV_CAPAB_SUPPORT_BTM	(1 << 0)
#define CSM_DRV_CAPAB_SUPPORT_HT	(1 << 1)
#define CSM_DRV_CAPAB_SUPPORT_VHT	(1 << 2)
#define CSM_DRV_CAPAB_SUPPORT_MONITOR	(1 << 3)
#define CSM_DRV_CAPAB_SUPPORT_ERW	(1 << 4)
#define CSM_DRV_CAPAB_SUPPORT_SPDIA	(1 << 5)
#define CSM_DRV_CAPAB_SUPPORT_DISASSOC	(1 << 6)
#define CSM_DRV_CAPAB_SUPPORT_OMONITOR	(1 << 7)
	uint8_t driver_cap;
#define CSM_DRV_SPDIA_REORDER		(1 << 0)
#define CSM_DRV_SPDIA_MODE_DATA		(1 << 1)
#define CSM_DRV_SPDIA_MODE_NDP		(1 << 2)
	uint8_t spdia_supported_feature;
	uint8_t spdia_sta_support_count;
	struct list_head spdia_sta_head;
	uint32_t driver_extcap;
#define DOT11_PHY_TYPE_FHSS		(1)
#define DOT11_PHY_TYPE_DSSS		(2)
#define DOT11_PHY_TYPE_IR		(3)
#define DOT11_PHY_TYPE_OFDM		(4)
#define DOT11_PHY_TYPE_HRDSSS		(5)
#define DOT11_PHY_TYPE_ERP		(6)
#define DOT11_PHY_TYPE_HT		(7)
#define DOT11_PHY_TYPE_DMG		(8)
#define DOT11_PHY_TYPE_VHT		(9)
	uint8_t phy_type;
	uint8_t channel;
	uint8_t operation_class;
	uint8_t ht_capability[HT_CAPABILITY_LEN];
	uint8_t ht_operation[HT_OPERATION_LEN];
	uint8_t vht_capability[VHT_CAPABILITY_LEN];
	uint8_t vht_operation[VHT_OPERATION_LEN];
	uint8_t he_capability[IEEE80211_HECAP_MAXLEN];
	uint8_t he_operation[IEEE80211_HEOP_MAXLEN];
	uint8_t txss;
	char ifname[IFNAMSIZ + 1];
	uint8_t ssid_len;
	char ssid[IEEE80211_SSID_MAXLEN + 1];
#define AC_MAXNUM	4
	espi_t espis[AC_MAXNUM];

	uint8_t hessid[ETH_ALEN];
#define BSS_EXTCAP_SUPPORT_SET_CC3rd	(1 << 0)
#define BSS_EXTCAP_SUPPORT_PMF_MFPR	(1 << 1)
#define BSS_EXTCAP_SUPPORT_PMF_MFPC	(1 << 2)
	uint32_t ext_cap;
	uint8_t country_code[2];

	uint8_t supp_extcap_mask[SUPP_EXTCAP_MASK_BYTES];
	uint8_t supp_elemid_mask[SUPP_EID_MASK_BYTES];
	uint8_t registrable_tx_frm_len;
	uint8_t registrable_tx_frm[REG_FRAME_MAXLEN];
	struct list_head txfrm_head;
	uint8_t registrable_rx_frm_len;
	uint8_t registrable_rx_frm[REG_FRAME_MAXLEN];
	struct list_head rxfrm_head;

#define BSS_REGISTRABLE_ASSOC		(1 << 0)
#define BSS_REGISTRABLE_REASSOC		(1 << 2)
#define BSS_REGISTRABLE_PROBE		(1 << 4)
#define BSS_REGISTRABLE_DISASSOC	(1 << 10)
#define BSS_REGISTRABLE_AUTH		(1 << 11)
#define BSS_REGISTRABLE_DEAUTH		(1 << 12)
#define BSS_REGISTRABLE_ACTION		(1 << 13)
	uint16_t registrable_mask;

#define BSS_FLAG_REMOTE (0x1)
#define BSS_FLAG_DOWN (0x2)
#define BSS_FLAG_MBO		(1 << 8)
#define BSS_FLAG_ACR		(1 << 9)
#define BSS_FLAG_DISALLOWED	(1 << 10)
#define BSS_FLAG_MAP_fBSS	(1 << 16)
#define BSS_FLAG_MAP_bBSS	(1 << 17)
#define BSS_FLAG_MAP_bSTA	(1 << 18)
	uint32_t flag;
	mobility_domain_t *md;
	csmpluginctx_t *drv;
} bss_table_t;

typedef enum {
	BW_20M = 0,
	BW_40M,
	BW_80M,
	BW_160M,

	BW_MAX,
} bw_e;

typedef struct {
	sta_cap_t capability;
	phyrate_t avg_tx_phyrate;
	timestamp_t last_tx_ts;
	phyrate_t avg_rx_phyrate;
	timestamp_t last_rx_ts;
	uint16_t rx_ss;
	phyrate_t supported_phyrate;
	timestamp_t ts_probe;
#define BAND_INFO_FLAG_VALID (0x1)
	uint32_t flag;
} sta_band_info_t;

#define CHAN_MASK_BYTES		((256 + (NBBY - 1)) / NBBY)
#define OPCLASS_MASK_BYTES	((256 + (NBBY - 1)) / NBBY)
typedef struct {
	struct list_head lh;
	uint8_t operating_class;
	uint8_t channels_included;
	uint8_t channels[CHAN_MASK_BYTES];
	uint8_t perference;
	uint8_t reason_code;
	uint8_t *attr;
} nonprefer_chan_t;

typedef struct {
	uint32_t tx_packets;
	uint32_t tx_bytes;
	uint32_t rx_packets;
	uint32_t rx_bytes;
	uint32_t tx_errors;
	uint32_t rx_errors;
	uint32_t tx_tries;
} link_stats_t;

typedef struct {
	uint8_t assoc_bssid[ETH_ALEN];
	uint8_t assoc_mdid[MDID_LEN];
	phyrate_t supported_phyrate;
	phyrate_t avg_tx_phyrate;
	phyrate_t last_tx_phyrate;
	timestamp_t last_tx_ts;
	phyrate_t last_rx_phyrate;
	phyrate_t avg_rx_phyrate;
	timestamp_t last_rx_ts;
	timestamp_t last_assoc_ts;
	bandwidth_t last_tx_bandwidth;
	bandwidth_t last_rx_bandwidth;
	phyrate_t inferred_tx_phyrate;
	uint32_t avg_airtime;
#define PKTS_PER_SEC_INVALID	(-1)
	uint32_t pkts_per_sec;
	uint8_t channel;
	uint8_t band;
	rssi_t last_rssi;
	rssi_t avg_rssi;
	uint8_t suppchan_2g_existed;
	uint8_t suppchan_5g_existed;
	uint8_t *supp_opclass_ie;
	uint8_t *rm_enabled_ie;
	/* Supported Channels element from (Re)Assoc Req */
	uint8_t suppchan_2g_masks[CHAN_MASK_BYTES];
	uint8_t suppchan_5g_masks[CHAN_MASK_BYTES];
	/* Non-preferred Channel Report attribute from (Re)Assoc Req/WNM Notification Req */
	struct list_head nonpref_chan_lh;
	/* Supported Operating Classes element from (Re)Assoc Req */
	uint8_t suppopclass_masks[OPCLASS_MASK_BYTES];

	uint16_t latest_assoc_len;
	uint8_t *latest_assoc;
	link_stats_t stats;
	uint8_t psk_keyid[PSK_KEYID_MAXLEN + 4];
} sta_assoc_info_t;

typedef struct {
	uint32_t supported_channel_mask;
	sta_cap_t supported_capability;
	uint16_t supported_rxss;
} sta_cap_info_t;

typedef struct {
	struct list_head lh;
	uint8_t bssid[ETH_ALEN];
	rssi_t last_rssi;
	timestamp_t last_ts;
	rssi_t ref_rssi;
	phyrate_t ref_phyrate;
	timestamp_t last_refresh_ts;
	uint8_t ch;
} sta_seen_bssid_t;

typedef struct {
	uint8_t mdid[MDID_LEN];
	struct list_head lh;
	/* head link for sta_seen_bssid */
	struct list_head seen_bssid_lh;
} sta_seen_mdid_t;

typedef struct {
	/* with embedded mac address */
	stah_t h;
	uint8_t MDID[MDID_LEN];
	sta_cap_info_t sta_info;
	sta_assoc_info_t assoc_info;
	/* head link for sta_seen_mdid */
	struct list_head seen_mdid_lh;

	/* internal control structure */
	sta_band_info_t sta_band_info[BAND_MAX];
	uint8_t band_mask;
	uint8_t last_band;
	uint8_t last_channel;
	timestamp_t last_rssi_ts;
#define STATION_FLAG_ASSOCIATED (0x1)
#define STATION_FLAG_AUTHED (0x2)
#define STATION_FLAG_BLACKLISTED (0x4)
	/* legacy1 station which do not have valid timestamp for last tx/rx */
#define STATION_FLAG_LEGACY1_STA (0x8)
#define STATION_FLAG_ASSOCINFO_FAKE	(0x40)
#define STATION_FLAG_MBO	(0x80)
	uint8_t flag;
	uint8_t mbo_cell_cap;
	uint8_t beaconreq_token;
	enum csm_node_type node_type;
	void *tx_phyrate_averager;
	void *rx_phyrate_averager;
	void *rssi_averager;
	/* for storing the historical data */
	void *pkts_persec_averager;
} sta_table_t;

void *csm_new(size_t size);

void *csm_get(void *obj);

void *csm_put(void *obj);
char *csm_get_next_plugin_name(DIR * dir);
mobility_domain_t *csm_find_mobility_domain(csmctx_t * csm,
					    uint8_t * mdid);
stah_t *stadb_sta_find(struct sta_sdb *db, uint8_t * mac);
stah_t *stadb_sta_find_unlock(struct sta_sdb *db, uint8_t * mac);
csmctx_t *csm_init();
void csm_attach_logic_to_mobility_domain(csmctx_t * csm, const char
					 *logic_name, uint8_t * mdid, void
					 *init_param);
void csm_attach_drv(csmctx_t * csm,
		    const char *drv_name, void *init_param);
void csm_attach_comm(csmctx_t * csm,
		     const char *comm_name, void *init_param);
void csm_attach_misc(csmctx_t * csm,
		     const char *misc_name, void *init_param);

int csm_update_bss_backbone(void *ctx, uint8_t *uplink,
	uint32_t type, uint16_t fixed_phyrate);

int
stadb_connect_signal_unlock(struct sta_sdb *db, uint32_t signal,
			    int recall, sta_signal_func_t func,
			    void *ctx, void *param, sta_signal_release_func_t cb);
int csm_create_station_db(csmctx_t * csm, int max_size);
int csm_create_bss_db(csmctx_t * csm, int max_size);
int csm_create_radio_db(csmctx_t *csm, int max_size);

void csm_update_uplink_sta_type(csmctx_t *csm, uint8_t *uplink, uint8_t *old_uplink);

#endif
