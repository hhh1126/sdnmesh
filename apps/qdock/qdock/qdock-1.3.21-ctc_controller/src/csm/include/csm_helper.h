/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSM_HELPER_H_
#define _CSM_HELPER_H_

typedef struct {
	union {
		int int_value;
		double double_value;
		const char *str_value;
		const void *object;
	};
} csm_param_value;

enum {
	CSM_PARAM_INT,
	CSM_PARAM_STRING,
	CSM_PARAM_DOUBLE,
	CSM_PARAM_OBJECT,
};

typedef struct {
	struct list_head lh;
	struct timeval timeout;
	csm_timer_func_t func;
	uint32_t interval;
	void *data1;
	void *data2;
} csm_timer_t;

typedef struct {
	int32_t value;
	timestamp_t ts;
} csm_history_t;

#define CSM_AVERAGER_GET_PREV_IND(_avg, _ind)	(((_ind) - 1) & (((_avg)->size) - 1))
typedef struct {
	uint16_t shift;
	uint32_t index;
	uint32_t size;
	uint32_t nums;
	csm_history_t history[0];
} csm_averager;

#define REJECT_WITH_NRIE	82
typedef struct {
	uint8_t sta[ETH_ALEN];
#define CSM_ERW_ACTION_DEL	0
#define CSM_ERW_ACTION_ADD	1
#define	CSM_ERW_ACTION_CLR_NR	8
	uint8_t action;
#define CSM_ERW_RSSI_MODE_NONE	0
#define CSM_ERW_RSSI_MODE_MIN	(1 << 1)
#define CSM_ERW_RSSI_MODE_MAX	(1 << 2)
	uint8_t rssi_mode;
	int8_t rssi;
	uint8_t mask;
	uint16_t reject_mode;
	uint16_t reject_payload_len;
	uint8_t *reject_payload;
} csm_erw_entry_t;

typedef struct {
	uint32_t nums;
#define CSM_MAX_ERW_ENTRIES	32
	csm_erw_entry_t entries[CSM_MAX_ERW_ENTRIES];
} csm_erw_list_t;

typedef struct {
	uint16_t period;	/* ms */
	uint8_t percent;	/* monitor on-time(on_period) is percentage of period? */
	uint16_t on_period;	/* percentage OR us */
	uint8_t nac_chan;	/* nac monitor channel */
} csm_intf_monitor_param_t;

typedef struct {
	uint8_t interw_en;	        /* enable or disable */
	uint8_t an_type;	        /* acccess network type */
	uint8_t hessid[ETH_ALEN];	/* global unique mac */
} csm_intf_interworking_param_t;

typedef struct {
#define CSM_INTF_FEAT_MONITOR			(1 << 3)
#define CSM_INTF_FEAT_MAP_BSTA			(1 << 7)
#define CSM_INTF_FEAT_OMONITOR_AUTO		(1 << 8)
#define CSM_INTF_FEAT_OMONITOR_ONDEMAND 	(1 << 9)
#define CSM_INTF_FEAT_INTERWORKINGPROBES 	(1 << 10)
#define CSM_INTF_FEAT_IGNORE_HWPBC		(1 << 15)
	uint32_t feat;
	uint32_t feat_mask;

	csm_intf_monitor_param_t mon_param;
	csm_intf_interworking_param_t interw_param;
} csm_intf_cfg_t;

#define BAND_IDX_MAX	7
struct band_info {
	uint8_t band_chan_step;                 /* step to next channel */
	uint8_t band_first_chan;                /* first channel in the band */
	int16_t band_chan_cnt;                  /* channels in the band */
};

typedef int (*table_filter_func_t) (stah_t *, void *, void *);

csmmsg_t *csm_new_msg(uint16_t id, uint8_t version, uint8_t coding,
		      uint8_t * bssid, size_t len);
void csm_unref_msg(csmmsg_t * msg);
csmmsg_t *csm_ref_msg(csmmsg_t * msg);
void csm_set_free_data(csmobj_t * obj, free_data_func free_data,
		       void *data);
csmmsg_t *csm_new_empty_msg(size_t len);
void csm_msg_set_body(csmmsg_t * msg, char *body, int len);

radio_table_t *csm_radio_find(struct sta_sdb *db, uint8_t *mac);
radio_table_t *csm_radio_find_or_add(struct sta_sdb *db, uint8_t *mac);
void csm_radio_put(radio_table_t *radio);
void *csm_bss_add(struct sta_sdb *db, uint8_t * mac);
void *csm_bss_find(struct sta_sdb *db, uint8_t * mac);
extern void csm_seen_bssid_del(sta_table_t *sta, uint8_t *bssid);
sta_seen_bssid_t *csm_seen_bssid_find_or_add(sta_table_t * sta,
					     uint8_t * mdid,
					     uint8_t * bssid);
int csm_push_cmd(void *ctx, csmmsg_t * action);
int csm_push_event(void *ctx, csmmsg_t * event);
uint32_t csm_station_age_out(stah_t * stah, stah_t ** pcandidateh,
			     void *data);
int stadb_sta_delete_unlock(struct sta_sdb *db, stah_t * stah);

extern stah_t *stadb_sta_add(struct sta_sdb *db, uint8_t * mac);
extern stah_t *stadb_sta_find_or_add(struct sta_sdb *db, uint8_t * mac);
extern int stadb_sta_delete(struct sta_sdb *db, uint8_t * mac);

extern struct sta_sdb *csm_get_station_table(void *ctx);
extern struct sta_sdb *csm_get_bss_table(void *ctx);
extern struct sta_sdb *csm_get_radio_table(void *ctx);
extern void csm_put_radio_table(struct sta_sdb *db);
extern struct sta_sdb *csm_get_devid_table(void *ctx);
extern void csm_put_devid_table(struct sta_sdb *db);
extern uint32_t csm_get_seen_bssid_age(sta_seen_bssid_t *seen_bssid);
extern struct sta_sdb *csm_get_station_table_snapshot(void *ctx);
extern void csm_put_station_table_snapshot(struct sta_sdb *db);
extern struct sta_sdb *csm_get_bss_table_snapshot(void *ctx);
extern void csm_put_bss_table_snapshot(struct sta_sdb *db);
extern stah_t *csm_find_station_snapshot(void *ctx, uint8_t * mac);
extern void csm_put_station_snapshot(stah_t * sta);
extern stah_t *csm_find_bss_snapshot(void *ctx, uint8_t * mac);
extern void csm_put_bss_snapshot(stah_t * bss);
extern int csm_deauth_sta(csmctx_t * csm, uint8_t * bss_mac,
			uint8_t * mac, uint16_t code);
#define CSM_DEAUTH_FLAG_BLACKLIST	(1 << 0)
#define CSM_DEAUTH_FLAG_DISASSOC	(1 << 1)
extern int csm_deauth_and_blacklist_sta(void *ctx, uint8_t * bss_mac,
					uint8_t * mac, uint16_t code,
					int flag);
extern int csm_process_sta_table_tlv(void *ctx, uint8_t * msg_payload);
extern int csm_process_bss_table_tlv(void *ctx, uint8_t *device_id, uint8_t * msg_payload);

extern sta_table_t **csm_station_list_get_by_filter(void *ctx,
						    table_filter_func_t
						    filter, void *data1,
						    void *data2);
extern void csm_station_list_put(sta_table_t ** stalist);
extern bss_table_t **csm_bss_list_get_by_filter(void *ctx,
						table_filter_func_t filter,
						void *data1, void *data2);
extern void csm_bss_list_put(bss_table_t ** bsslist);

extern int csm_timer_cancel(void *ctx, csm_timer_func_t func,
			    void *data1, void *data2);
extern int csm_timer_register(void *ctx, uint32_t msecs,
			      csm_timer_func_t func, void *data1,
			      void *data2, int repeat);
extern stah_t *stadb_sta_find_or_add_ext1(struct sta_sdb * db, uint8_t * mac,
		                                   sta_early_init_func func, void *data1,
										                                      void *data2);
extern void csm_start_fat_monitor(void *handle, uint32_t secs);
extern void csm_start_sta_stats_monitor(void *handle, uint32_t secs);
extern int csm_start_monitor(void *handle, uint8_t *bssid,
				  uint32_t period, uint32_t duty_cycle);
extern int csm_spdia_sta_ctrl(void *handle, uint8_t *mac, uint32_t period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth);
extern int csm_param_get_value(void *handle, csm_param_value * value,
			       const char *key, int type, int index);
extern int csm_object_param_get_value(void *handle, const void *object,
	csm_param_value *value, const char *key, int type, int index);
extern void *csm_averager_create(uint16_t shift);
extern void csm_averager_destroy(void *p);
extern int32_t csm_averager_get_value(void *p, uint16_t age);
extern int csm_averager_add_value(void *p, int32_t value, timestamp_t ts);
extern void csm_averager_set_value(void *p, int32_t value);
extern void csm_bss_delete(csmctx_t *csm, bss_table_t *bss);
extern int csm_bss_delete_remote(void *ctx);
extern int csm_sta_update_assoc_bss(csmctx_t * csm,
				    uint8_t * bssid, uint8_t * sta_addr);
extern int csm_bss_trans_req(void *ctx, uint8_t * bss, uint8_t * payload,
			     uint32_t payload_len);
extern int csm_station_delete_association(void *ctx, uint8_t * bssid,
					  uint8_t * sta_mac);
extern int csm_bss_update(void *ctx, uint8_t * bssid, uint16_t status);

extern bss_table_t *csm_bss_find_or_add(struct sta_sdb *db, uint8_t *device_id,
					uint8_t * mac, void *drv);

extern void csm_bss_put(bss_table_t * bss);

extern sta_table_t *csm_station_add(struct sta_sdb * db, uint8_t * mac);

extern sta_table_t *csm_station_find(struct sta_sdb * db, uint8_t * mac);

extern sta_table_t *csm_station_find_or_add(struct sta_sdb * db,
					    uint8_t * mac);

extern void csm_station_put(sta_table_t * sta);
extern int csm_station_delete_related(csmctx_t * csm, uint8_t * mac);
extern int csm_timer_init(csmctx_t * ctx);
extern int csm_devid_delete_related(csmctx_t *csm, bss_table_t *bss);

extern int csm_set_erw(void *ctx, uint8_t *bss_mac, csm_erw_list_t *list);
extern uint32_t csm_get_sta_supported_maxphyrate(sta_table_t *sta);
extern bw_e csm_get_bss_bandwidth(bss_table_t *bss);
extern uint32_t csm_get_bss_supported_maxphyrate(bss_table_t *bss);

extern int csm_build_sta_ies(sta_table_t *sta,
	uint8_t *frm, uint32_t len);
extern uint8_t csm_get_bw20_opclass(uint8_t ch);
extern uint8_t csm_get_global_opclass(uint8_t *cc, uint8_t opclass);
extern void csm_parse_supp_opcalss(bss_table_t *bss,
	sta_table_t *sta, uint8_t *frm, uint8_t len);
extern void csm_parse_supp_chan(sta_table_t *sta,
	uint8_t *frm, uint8_t len);
extern void csm_parse_mbo_nonpref_chan(sta_table_t *sta,
	uint8_t *frm, uint8_t len);
extern void csm_free_nonpref_chans(sta_table_t *sta);
extern uint8_t *csm_store_ie(uint8_t *frm);
extern void csm_parse_mbo_cell_cap(sta_table_t *sta,
	uint8_t *frm, uint8_t len);

typedef void (*init_block_t)(void);
typedef int (*check_block_t)(uint16_t);
typedef void (*parse_ie_t)(void **, uint8_t *, uint16_t, uint16_t);
typedef void (*process_block_t)(void *, void *, uint8_t *, int);
extern void csm_parse_rpe_tlv(void *ctx, uint8_t *frm, uint16_t frm_len,
	init_block_t init_cb, check_block_t check_cb,
	parse_ie_t parse_cb, process_block_t process_cb);

typedef struct {
	uint8_t *frm_info;
	uint8_t *frm;
} RPE_FRAME_PARSE_T;
extern void csm_parse_rpe_frame_block(void **ies,
	uint8_t *frm, uint16_t type, uint16_t len);

typedef int (*process_ieee80211_fixed_t)(void *ctx, uint8_t *frm, uint8_t *efrm);
typedef void (*process_ieee80211_ie_t)(void *ctx, uint8_t *frm);
extern int csm_process_frame(uint8_t wh_included, uint8_t *frame, uint32_t len,
	void *process_ctx, process_ieee80211_fixed_t process_fixed_cb,
	process_ieee80211_ie_t process_ie_cb);

extern int csm_check_frame_ie_len(uint32_t ie_offset, uint8_t *frame, uint32_t len);
extern int csm_tx_rpe_msg(void *ctx, uint8_t *bssid, uint8_t *msg, uint32_t len);
extern int csm_rx_rpe_msg(void *ctx, uint8_t *bssid, uint8_t *msg, uint32_t len);

extern void csm_hessids_reselect(csmctx_t *csm);
extern void csm_hessid_update(csmctx_t *csm, uint8_t *old_mdid,
	uint8_t *mdid, uint8_t *mac, csmpluginctx_t *ctx);
extern uint32_t csm_build_hessid_mdid_maps(void *ctx,
	uint8_t *buf, uint32_t space);
extern void csm_role_changed_callback(csmctx_t *csm,
	uint8_t o_role, uint8_t n_role);

extern int csm_check_registrable_frame_matched(bss_table_t *bss,
	int is_rx, uint8_t subtype,
	const uint8_t *match, uint8_t match_len);
extern void csm_update_registrable_frame(csmctx_t *csm,
	bss_table_t *bss, int is_rx, uint8_t subtype,
	uint8_t *match, uint8_t match_len);

extern int csm_build_history_pkts(sta_table_t *sta,
	uint8_t *frm, uint32_t len);
extern uint32_t csm_get_lower_pkts_nums(sta_table_t *sta,
	uint32_t threshold);

extern void csm_update_bss_into_radio(csmctx_t *csm, bss_table_t *bss, uint8_t *radio_id);
extern opclass_entry_t *csm_find_radio_opclass_entry(radio_table_t *radio, uint8_t opclass);
extern opclass_entry_t *csm_find_and_add_radio_opclass_entry(radio_table_t *radio, uint8_t opclass);
extern chan_entry_t *csm_find_opclass_chan_entry(opclass_entry_t *opclass_info, uint8_t ch);
extern chan_entry_t *csm_find_and_add_opclass_chan_entry(opclass_entry_t *opclass_info, uint8_t ch);

extern int csm_set_radio_channel(void *ctx, uint8_t *rmac,
	uint8_t opcls, uint8_t ch, uint8_t txpwr, uint8_t is_20M);
extern int csm_set_intf_cfg(void *ctx, uint8_t *bss_mac,
	csm_intf_cfg_t *cfg);
extern int csm_sta_roam(void *ctx, uint8_t *mac,
	uint8_t *target, uint8_t ch, uint8_t opclass);
#endif
