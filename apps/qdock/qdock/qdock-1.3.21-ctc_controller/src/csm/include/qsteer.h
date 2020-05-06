/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/
/* This head file including all shadow qsteer APIs */

#ifndef _QSTEER_H_
#define _QSTEER_H_


#include "csm.h"

typedef struct sta_sdb NeighSTATable;
typedef struct sta_sdb BSSTable;
typedef struct sta_sdb RadioTable;

static inline NeighSTATable *QSteer_CSM_getSTATable(void *plugin_ctx)
{
	return csm_get_station_table_snapshot(plugin_ctx);
}

static inline void QSteer_CSM_putSTATable(NeighSTATable *tbl)
{
	csm_put_station_table_snapshot(tbl);
}

static inline BSSTable *QSteer_CSM_getBSSTable(void *plugin_ctx)
{
	return csm_get_bss_table_snapshot(plugin_ctx);
}

static inline void QSteer_CSM_putBSSTable(BSSTable *tbl)
{
	csm_put_bss_table_snapshot(tbl);
}

static inline RadioTable *QSteer_CSM_getRadioTable(void *plugin_ctx)
{
	return csm_get_radio_table(plugin_ctx);
}

static inline void QSteer_CSM_putRadioTable(RadioTable *tbl)
{
	csm_put_radio_table(tbl);
}

static inline int Steer_CSM_deauth(void *plugin_ctx, uint8_t * bss_mac,
				   uint8_t * mac, uint16_t code,
				   int flag)
{
	return csm_deauth_and_blacklist_sta(plugin_ctx, bss_mac, mac, code,
					    flag);

}

static inline int QSteer_CSM_erw(void *plugin_ctx, uint8_t *bss_mac,
				csm_erw_list_t *list)
{
	return csm_set_erw(plugin_ctx, bss_mac, list);
}

static inline int QSteer_CSM_staRoam(void *plugin_ctx, uint8_t *mac,
	uint8_t *target, uint8_t ch, uint8_t opclass)
{
	return csm_sta_roam(plugin_ctx, mac, target, ch, opclass);
}

static inline int QSteer_CSM_setIntfCfg(void *plugin_ctx, uint8_t *bss_mac,
				csm_intf_cfg_t *cfg)
{
	return csm_set_intf_cfg(plugin_ctx, bss_mac, cfg);
}

static inline int QSteer_CSM_updateSTATable(void *plugin_ctx,
					    uint8_t * msg_payload)
{
	return csm_process_sta_table_tlv(plugin_ctx, msg_payload);
}

static inline int QSteer_CSM_updateBSSTable(void *plugin_ctx, uint8_t *device_id,
					    uint8_t * msg_payload)
{
	return csm_process_bss_table_tlv(plugin_ctx, device_id, msg_payload);
}

static inline int QSteer_CSM_updateBssBackbone(void *plugin_ctx, uint8_t *uplink,
					uint32_t type, uint16_t fixed_phyrate)
{
	return csm_update_bss_backbone(plugin_ctx, uplink, type, fixed_phyrate);
}

static inline int QSteer_CSM_setChannel(void *plugin_ctx, uint8_t *radio,
	uint8_t opclass, uint8_t channel, uint8_t txpwr, uint8_t is_20M)
{
	return csm_set_radio_channel(plugin_ctx, radio,
		opclass, channel, txpwr, is_20M ? 20 : 0);
}

static inline int QSteer_CSM_BssTransReq(void *plugin_ctx, uint8_t * bss,
					 uint8_t * msg_payload,
					 uint32_t payload_len)
{
	return csm_bss_trans_req(plugin_ctx, bss, msg_payload,
				 payload_len);
}

static inline int QSteer_CSM_STA_Deauth(void *plugin_ctx, uint8_t * bss,
					uint8_t * sta)
{
	return csm_station_delete_association(plugin_ctx, bss, sta);
}

static inline int QSteer_CSM_STA_Update_Assoc_BSS(void *plugin_ctx,
						  uint8_t * bss,
						  uint8_t * sta)
{
	return
	    csm_sta_update_assoc_bss((csmctx_t
				      *) (((csmpluginctx_t *)
					   plugin_ctx)->csm), bss, sta);
}

static inline int QSteer_CSM_StartFATMonitoring(void *plugin_ctx, uint32_t period)
{
	csm_start_fat_monitor(plugin_ctx, period);
	return 0;
}

static inline int QSteer_CSM_SetStatsPeriod(void *plugin_ctx, uint32_t period)
{
	csm_start_sta_stats_monitor(plugin_ctx, period);
	return 0;
}

static inline int QSteer_CSM_StartMonitoring(void *plugin_ctx, uint8_t *bssid,
						uint32_t period, uint32_t duty_cycle)
{
	return csm_start_monitor(plugin_ctx, bssid, period, duty_cycle);
}

static inline int QSteer_CSM_UpdateBSS(void *ctx, uint8_t * bssid, uint16_t status)
{
	return csm_bss_update(ctx, bssid, status);
}

static inline int QSteer_CSM_RPEMsgTx(void *ctx, uint8_t *bssid, uint8_t *msg, uint32_t len)
{
	return csm_tx_rpe_msg(ctx, bssid, msg, len);
}

static inline void QSteer_Hessid_update(void *ctx, uint8_t *mdid, uint8_t *bssid)
{
	if (!ctx || !mdid || !bssid)
		return;
	csm_hessid_update((csmctx_t *)(((csmpluginctx_t *)ctx)->csm),
		NULL, mdid, bssid, NULL);
}

static inline void QSteer_RoleChanged_Callback(void *ctx, uint8_t old_role, uint8_t new_role)
{
	if (!ctx || (old_role == new_role))
		return;
	return csm_role_changed_callback((csmctx_t *)(((csmpluginctx_t *)ctx)->csm),
		old_role, new_role);
}

static inline int SONiQ_CSM_CSiQ_ctrl(void *ctx, uint8_t *sta, uint32_t period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth)
{
	return csm_spdia_sta_ctrl(ctx, sta, period, reorder, mode, ng, smooth);
}
#endif
