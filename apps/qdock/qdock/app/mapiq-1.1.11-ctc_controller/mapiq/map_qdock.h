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

#ifndef __MAP_QDOCK_H__
#define __MAP_QDOCK_H__

#include "csm.h"
#include "qsteer.h"

#define MAP_RECONF_BSS_MBOIE		(1 << 0)
#define MAP_RECONF_BSS_ADVERIE		(1 << 1)
#define MAP_RECONF_BSS_INTERWORKIE	(1 << 2)
#define MAP_RECONF_BSS_RMCAPIE		(1 << 3)
#define MAP_RECONF_BSS_EXTCAP		(1 << 8)
#define MAP_RECONF_BSS_3RDCC		(1 << 9)
#define MAP_RECONF_BSS_FRAME_REGISTERED	(1 << 16)
#define MAP_RECONF_BSS_VERIFY_CAPA	(1 << 30)
#define MAP_RECONF_BSS_RESET		(1 << 31)

#define MAP_RECONF_BSS_APPIE	(MAP_RECONF_BSS_MBOIE | MAP_RECONF_BSS_ADVERIE\
			| MAP_RECONF_BSS_INTERWORKIE | MAP_RECONF_BSS_RMCAPIE)
#define MAP_RECONF_BSS_USERCAP	(MAP_RECONF_BSS_APPIE | MAP_RECONF_BSS_EXTCAP	\
			| MAP_RECONF_BSS_3RDCC)
#define MAP_RECONF_BSS_ALL	(MAP_RECONF_BSS_USERCAP		\
				| MAP_RECONF_BSS_FRAME_REGISTERED | MAP_RECONF_BSS_VERIFY_CAPA)
#define MAP_IS_RECONF_BSS_RESET(_flag)	((_flag) & MAP_RECONF_BSS_RESET)

typedef struct map_entry {
	struct list_head lh;

	stah_t *stah;
} map_entry_t;

extern void map_add_entry(struct list_head *phead, stah_t *stah);
extern void map_free_entry(map_entry_t *entry);

extern sta_table_t *map_get_stadb_sta(uint8_t *mac);
extern bss_table_t *map_get_stadb_bss(uint8_t *mac);
extern radio_table_t *map_get_stadb_radio(uint8_t *mac);

extern void map_find_staes_with_bssid(struct list_head *phead,
	const uint8_t *mac, const uint8_t *bssid);
extern void map_find_non_assoc_staes(struct list_head *phead);
extern void map_find_radios(struct list_head *phead,
	uint8_t *radio_id);
extern void map_find_bsses(struct list_head *phead, uint8_t *radio_id,
        uint8_t *dev_id);
extern sta_seen_bssid_t *map_find_seenbssid(sta_table_t *sta,
	uint8_t *bssid);
extern bss_table_t *map_get_radio_first_bss(radio_table_t *radio);
extern bss_table_t *map_get_radio_first_vap_in_repeater(radio_table_t *radio);

#define map_stadb_stah_ref(_stah)	do { if(_stah)	csm_get(_stah);} while(0)
#define map_stadb_stah_unref(_stah)	do { if(_stah)	csm_put(_stah);} while(0)

#define map_get_sta_table		csm_get_station_table_snapshot
#define map_put_sta_table		csm_put_station_table_snapshot
#define map_get_bss_table		csm_get_bss_table_snapshot
#define map_put_bss_table		csm_put_bss_table_snapshot
#define map_get_radio_table		csm_get_radio_table
#define map_put_radio_table		csm_put_radio_table

#define MAP_STA_IS_ASSOCIATED(_sta)	STA_IS_ASSOCIATED(_sta)

#define map_check_frame_registrable      csm_check_registrable_frame_matched

typedef csmmsgh_t	map_rpemsg_t;
typedef tlv_t		map_rpetlv_t;
typedef csm_intf_cfg_t	map_intf_feat_t;

#define MAP_DEAUTH_CODE_DEFAULT			(1)	/* Unspecified reason */
static inline int map_deauth_sta(uint8_t *bss,
	uint8_t *sta, int is_deauth, uint16_t code)
{
	int flag = 0;
	if (!is_deauth)
		flag |= CSM_DEAUTH_FLAG_DISASSOC;
	return Steer_CSM_deauth(g_ctx.ctx, bss, sta, code, flag);
}

static inline int map_send_rpe(uint8_t *bss,
	uint8_t *rpe, uint32_t len)
{
	csm_tx_rpe_msg(g_ctx.ctx, bss, rpe, len);
	return 0;
}

static inline int map_set_intf_feat(uint8_t *bss, map_intf_feat_t *feat)
{
	return QSteer_CSM_setIntfCfg(g_ctx.ctx, bss, feat);
}

static inline int map_set_radio_power(uint8_t *radio_mac, uint8_t opclass,
	uint8_t chan, uint8_t txpower)
{
	return QSteer_CSM_setChannel(g_ctx.ctx, radio_mac, opclass,
		chan, txpower, 0);
}

static inline int map_start_fat_monitoring(uint16_t period)
{
	csm_start_fat_monitor(g_ctx.ctx, period);
	return 0;
}

static inline int map_start_stat_monitoring(uint16_t period)
{
	csm_start_sta_stats_monitor(g_ctx.ctx, period);
	return 0;
}

static inline int map_start_monitoring(uint8_t *bssid,
	uint16_t period, uint16_t duty_cycle)
{
	csm_start_monitor(g_ctx.ctx, bssid, period, duty_cycle);
	return 0;
}

static inline int map_set_off_chan_monitoring(uint8_t *bssid,
	csm_intf_cfg_t *cfg)
{
	return csm_set_intf_cfg(g_ctx.ctx, bssid, cfg);
}

static inline int map_start_roam_wdev(uint8_t *dev_mac,
	uint8_t *target_mac, int chan, int opclass)
{
	return QSteer_CSM_staRoam(g_ctx.ctx, dev_mac, target_mac, chan, opclass);
}

static inline int map_set_erw(uint8_t *bssid, csm_erw_list_t *erws)
{
	return csm_set_erw(g_ctx.ctx, bssid, erws);
}

#define map_get_age(_ts)		csm_get_age(_ts)

#define MAP_RPE_MAX_LEN		4096
#define MAP_RPE_VER		CSM_RPE_VER
#define MAP_RPE_IE_LEN		CSM_IE_LEN

extern int map_conf_appies(bss_table_t *bss,
	uint32_t mask, uint8_t *ies, uint32_t len);
extern int map_conf_extcap(bss_table_t *bss,
	uint8_t *extcap, uint8_t *extcap_mask, uint32_t len);
extern void map_conf_bss_maptype(bss_table_t *bss, int fbss, int bbss);
extern void map_conf_backhaul_sta(bss_table_t *bss, int bsta);
extern int map_cfg_chan(uint8_t *mac, uint8_t opclass,
	uint8_t chan, uint8_t txpower);
extern opclass_entry_t *map_get_radio_opclass_entry(radio_table_t *radio);
extern uint8_t map_get_radio_phytype(radio_table_t *radio);
extern uint8_t map_get_radio_feature(radio_table_t *radio);
extern int map_roam_wdev_to_target_bss(uint8_t *dev_mac,
	uint8_t *target_mac, int chan, int opclass);
extern bss_table_t *map_get_local_bss_by_ssid(char *ssid);
extern int map_get_bss_eatf(bss_table_t *bss);
extern void map_start_fat_monitoring_timer(uint16_t fat_period);
extern void map_start_stat_monitoring_timer(uint16_t stat_period);
extern void map_send_frame_reg_rpe(bss_table_t *bss, uint8_t subtype,
	uint8_t *match, uint32_t match_len, uint32_t rx_mode);
extern uint8_t *map_parse_frame(uint8_t *pos, uint16_t payload_len,
	uint16_t *type_len);
extern int map_add_sta_filter_rule(uint8_t *dev_id, uint8_t *sta,
	uint8_t rssi_mode, int8_t rssi, uint32_t mask, uint16_t reject_mode,
	uint8_t *reject_payload, uint16_t reject_payload_len);
extern int map_del_sta_filter_rule(uint8_t *dev_id, uint8_t *sta);
extern void map_start_chan_monitoring();
extern int map_set_intf_mon_chan_conf(uint8_t *radio_id,
	uint8_t opclass, uint8_t chan);
extern void map_send_frame_to_rpe(uint8_t *bssid,
	uint8_t *frame, uint16_t frame_len);

#endif
