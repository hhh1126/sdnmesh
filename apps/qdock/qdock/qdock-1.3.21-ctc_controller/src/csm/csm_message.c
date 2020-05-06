/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <pthread.h>
#ifdef Q_OPENWRT
#include <limits.h>
#endif
#include "csm.h"
#define PPREFIX "csmmsg: "

static int csm_process_event_intf_status(csmctx_t * csm, csmmsgh_t * h,
					 bss_table_t * bss,
					 drvctx_t * drv);
static int csm_process_event_intf_info(csmctx_t * csm, csmmsgh_t * h,
				       bss_table_t * bss, drvctx_t * drv);
static int csm_process_event_probe_req(csmctx_t * csm, csmmsgh_t * h,
				       bss_table_t * bss, drvctx_t * drv);
static int csm_process_event_connect_complete(csmctx_t * csm,
					      csmmsgh_t * h,
					      bss_table_t * bss,
					      drvctx_t * drv);
static int csm_process_event_deauth(csmctx_t * csm, csmmsgh_t * h,
				    bss_table_t * bss, drvctx_t * drv);
static int csm_process_event_disassoc(csmctx_t * csm, csmmsgh_t * h,
				      bss_table_t * bss, drvctx_t * drv);
static int csm_process_event_sta_phy_stats(csmctx_t * csm, csmmsgh_t * h,
					   bss_table_t * bss,
					   drvctx_t * drv);
static int csm_process_event_bss_trans_status(csmctx_t * csm,
					      csmmsgh_t * h,
					      bss_table_t * bss,
					      drvctx_t * drv);
static int csm_process_event_nonassoc_sta_phy_stats(csmctx_t * csm,
						    csmmsgh_t * h,
						    bss_table_t * bss,
						    drvctx_t * drv);
static int csm_process_event_assoc(csmctx_t * csm,
					csmmsgh_t * h,
					bss_table_t * bss,
					drvctx_t * drv);
static int csm_process_event_frame(csmctx_t * csm, csmmsgh_t * h,
					   bss_table_t * bss,
					   drvctx_t * drv);

static int csm_process_event_radio_info(csmctx_t *csm, csmmsgh_t *h,
	bss_table_t *bss, drvctx_t *drv);
static int csm_process_event_radio_status(csmctx_t *csm, csmmsgh_t *h,
	bss_table_t *bss, drvctx_t *drv);
static int csm_process_assoc_additional_info(csmctx_t *csm, csmmsgh_t *h,
	bss_table_t *bss, drvctx_t *drv);
static int csm_skip_event(csmctx_t * csm, csmmsgh_t * h,
			      bss_table_t * bss, drvctx_t * drv);


static int csm_process_cmd_common_t(csmctx_t * csm, csmmsgh_t * h,
				  bss_table_t * bss, drvctx_t * drv);
static int csm_process_cmd_sta_mac_filter(csmctx_t * csm, csmmsgh_t * h,
					  bss_table_t * bss,
					  drvctx_t * drv);

static csm_event_handler g_csm_event_handler[] = {
	{EVENT_INTF_STATUS, "EVENT_INTF_STATUS",
	 csm_process_event_intf_status, 0},
	{EVENT_INTF_INFO, "EVENT_INTF_INFO", csm_process_event_intf_info,
	 0},
	{EVENT_PROBE_REQ, "EVENT_PROBE_REQ", csm_process_event_probe_req,
	 0},
	{EVENT_CONNECT_COMPLETE, "EVENT_CONNECT_COMPLETE",
	 csm_process_event_connect_complete, 0},
	{EVENT_DEAUTH, "EVENT_DEAUTH", csm_process_event_deauth, 0},
	{EVENT_DISASSOC, "EVENT_DISASSOC", csm_process_event_disassoc, 0},
	{EVENT_STA_PHY_STATS, "EVENT_STA_PHY_STATS",
	 csm_process_event_sta_phy_stats, 0},
	{EVENT_BSS_TRANS_STATUS, "EVENT_BSS_TRANS_STATUS",
	 csm_process_event_bss_trans_status, 0},
	{EVENT_NONASSOC_STA_PHY_STATS, "EVENT_NONASSOC_STA_PHY_STATS",
	 csm_process_event_nonassoc_sta_phy_stats, 0},
	{EVENT_AUTH, "EVENT_AUTH",
	 csm_skip_event, 0},
	{EVENT_ASSOC, "EVENT_ASSOC", csm_process_event_assoc, 0},
	{EVENT_FRAME, "EVENT_FRAME", csm_process_event_frame, 0},
	{EVENT_RADIO_INFO, "EVENT_RADIO_INFO", csm_process_event_radio_info, 0},
	{EVENT_RADIO_STATUS, "EVENT_RADIO_STATUS", csm_process_event_radio_status, 0},
	{EVENT_ROAM_FAIL, "EVENT_ROAM_FAIL", csm_skip_event, 0},
	{EVENT_ASSOC_ADDITIONAL_INFO, "EVENT_ASSOC_ADDITIONAL_INFO",
	 csm_process_assoc_additional_info, 0},
	{EVENT_SPDIA_INFO, "EVENT_SPDIA_INFO",
	 csm_skip_event, 0},
	{-1, NULL, NULL, 0}
};

static csm_cmd_handler g_csm_cmd_handler[] = {
	{CMD_INIT, "CMD_INIT", csm_process_cmd_common_t, 0},
	{CMD_DEINIT, "CMD_DEINIT", csm_process_cmd_common_t, 0},
	{CMD_GET_INTF_STATUS, "CMD_GET_INTF_STATUS",
	 csm_process_cmd_common_t, 0},
	{CMD_GET_INTF_INFO, "CMD_GET_INTF_INFO",
	 csm_process_cmd_common_t, 0},
	{CMD_DEAUTH, "CMD_DEAUTH", csm_process_cmd_common_t, 0},
	{CMD_DISASSOC, "CMD_DISASSOC", csm_process_cmd_common_t, 0},
	{CMD_STA_MAC_FILTER, "CMD_STA_MAC_FILTER",
	 csm_process_cmd_sta_mac_filter, 0},
	{CMD_GET_STA_STATS, "CMD_GET_STA_STATS",
	 csm_process_cmd_common_t, 0},
	{CMD_BSS_TRANS_REQ, "CMD_BSS_TRANS_REQ",
	 csm_process_cmd_common_t, 0},
	{CMD_START_FAT_MONITORING, "CMD_START_FAT_MONITORING",
	 csm_process_cmd_common_t, 0},
	{CMD_MONITOR_START, "CMD_MONITOR_START",
	 csm_process_cmd_common_t, 0},
	{CMD_MONITOR_STOP, "CMD_MONITOR_STOP",
	 csm_process_cmd_common_t, 0},
	{CMD_GET_NONASSOC_STATS, "CMD_GET_NONASSOC_STATS",
	 csm_process_cmd_common_t, 0},
	{CMD_FRAME, "CMD_FRAME",
	 csm_process_cmd_common_t, 0},
	{CMD_REGISTER_FRAME, "CMD_REGISTER_FRAME",
	 csm_process_cmd_common_t, 0},
	{CMD_SET_USER_CAP, "CMD_SET_USER_CAP",
	 csm_process_cmd_common_t, 0},
	{CMD_SET_CHAN, "CMD_SETCHAN", csm_process_cmd_common_t, 0},
	{CMD_ROAM, "CMD_ROAM", csm_process_cmd_common_t, 0},
	{CMD_SET_INTF_CFG, "CMD_SET_INTF_CFG",
	 csm_process_cmd_common_t, 0},
	{CMD_SPDIA_CTRL, "CMD_SPDIA_CTRL",
	 csm_process_cmd_common_t, 0},
	{-1, NULL, NULL, 0}
};

struct frame_ctx {
	csmctx_t *csm;
	bss_table_t *bss;
	sta_table_t *sta;
	union {
		uint32_t nonpref_channel_ies;
	} u;
};
#define GET_STA_FROM_FRAME_CTX(_ctx)	(((struct frame_ctx *)(_ctx))->sta)
#define GET_BSS_FROM_FRAME_CTX(_ctx)	(((struct frame_ctx *)(_ctx))->bss)
#define GET_CSM_FROM_FRAME_CTX(_ctx)	(((struct frame_ctx *)(_ctx))->csm)
static void csm_process_assoc_req_ie(void *ctx,
	uint8_t *frm);

csm_event_handler *csm_get_event_handler(int16_t id)
{
	csm_event_handler *handler = g_csm_event_handler;
	while (handler->id != -1) {
		if (handler->id == id) {
			handler->cnt++;
			return handler;
		}
		handler++;
	}
	return NULL;
}

csm_cmd_handler *csm_get_cmd_handler(int16_t id)
{
	csm_cmd_handler *handler = g_csm_cmd_handler;
	while (handler->id != -1) {
		if (handler->id == id) {
			handler->cnt++;
			return handler;
		}
		handler++;
	}
	return NULL;
}


int16_t csm_tlv_vlen(uint16_t type)
{
	switch (type) {
	case TLVTYPE_IFNAME:
	case TLVTYPE_SSID:
	case TLVTYPE_FRAME:
		return 0;	/* variable */
		break;
	case TLVTYPE_MAC_MDID:
	case TLVTYPE_SEEN_BY_COMM:
	case TLVTYPE_STA_MAC:
	case TLVTYPE_STA_INFO_COMM:
	case TLVTYPE_TS_LAST_RX:
	case TLVTYPE_AGE_LAST_RX:
	case TLVTYPE_TS_LAST_TX:
	case TLVTYPE_AGE_LAST_TX:
	case TLVTYPE_STA_RSSI_COMM:
	case TLVTYPE_RX_PHYRATE_COMM:
	case TLVTYPE_VHT_OPERATION:
	case TLVTYPE_BACKBONE_INFO:
		return 8;
		break;
	case TLVTYPE_CH_CHANGE_INFO:
	case TLVTYPE_CHANNEL_BAND:
	case TLVTYPE_CHANNEL_BAND_CC:
	case TLVTYPE_RX_PHYRATE:
	case TLVTYPE_TX_PHYRATE:
	case TLVTYPE_SUPPORTED_PHYRATE_COMM:
	case TLVTYPE_AVERAGE_FAT:
	case TLVTYPE_AVG_FAT_COMM:
	case TLVTYPE_INTERFACE_CAPABILITY:
	case TLVTYPE_INTERFACE_FEAT_COMM:
	case TLVTYPE_RSSI:
	case TLVTYPE_RSSI_ADV:
	case TLVTYPE_BEACON_INTERVAL:
	case TLVTYPE_NODE_TYPE:
	case TLVTYPE_BL_MASK:
	case TLVTYPE_STATUS_CODE:
	case TLVTYPE_NRIE_INDEX:
	case TLVTYPE_EXT_INTF_CAPABILITY:
	case TLVTYPE_PKT_CNT:
	case TLVTYPE_BSS_STATUS_COMM:
	case TLVTYPE_SPDIA_SUPPORTED_FEATURES:
	case TLVTYPE_SPDIA_CAPABILITIES:
		return 4;
		break;
	case TLVTYPE_HT_CAPABILITY:
		return 28;
		break;
	case TLVTYPE_HT_OPERATION:
		return 24;
		break;
	case TLVTYPE_VHT_CAPABILITY:
		return 16;
		break;
	default:
		return -1;	/* invalid */
		break;
	}
	return -1;
}

uint32_t csm_encap_tlv(uint8_t * start, uint16_t type, void *value,
		  uint16_t value_len)
{
	tlv_t *tlv = (tlv_t *) start;

	tlv->type = host_to_le16(type);
	tlv->len = host_to_le16(value_len);
	memcpy(tlv->value, value, value_len);

	return CSM_IE_LEN(value_len) + sizeof(tlv_t);
}

static inline void csm_sta_infer_and_update_ht_supported(uint8_t *cap, phyrate_t max_phyrate)
{
	sta_cap_t *capability = (sta_cap_t *)cap;

	if (capability->vht_supported
		|| capability->ht_bw == 1
		|| max_phyrate > 54) {
		capability->ht_supported = 1;
	} else {
		/* others condition we assume non-ht/legacy sta */
		capability->ht_supported = 0;
	}
}

static inline void csm_sta_update_supported_capability(sta_table_t * sta, uint8_t cap, uint8_t save_11v)
{
	sta_cap_t capability;
	capability.cap = cap;

	if(capability.ht_bw > sta->sta_info.supported_capability.ht_bw)
		sta->sta_info.supported_capability.ht_bw = capability.ht_bw;
	if(capability.vht_bw > sta->sta_info.supported_capability.vht_bw)
		sta->sta_info.supported_capability.vht_bw = capability.vht_bw;
	if(save_11v)
		sta->sta_info.supported_capability.bss_transition_supported = capability.bss_transition_supported;
	if(capability.vht_supported > sta->sta_info.supported_capability.vht_supported)
		sta->sta_info.supported_capability.vht_supported = capability.vht_supported;
	if(capability.mu_beamformer_supported > sta->sta_info.supported_capability.mu_beamformer_supported)
		sta->sta_info.supported_capability.mu_beamformer_supported = capability.mu_beamformer_supported;
	if(capability.mu_beamformee_supported > sta->sta_info.supported_capability.mu_beamformee_supported)
		sta->sta_info.supported_capability.mu_beamformee_supported = capability.mu_beamformee_supported;
	if(capability.ht_supported > sta->sta_info.supported_capability.ht_supported)
		sta->sta_info.supported_capability.ht_supported = capability.ht_supported;
}

int csm_sta_phy_stats_event_filter(sta_table_t *sta, bss_table_t *bss,
				csmmsgh_t *h, int type)
{
	if ((sta) && (bss) && STA_IS_ASSOCIATED(sta)
	    && !IS_ASSOCIATED_WITH(sta, bss->h.mac)
	    && le_to_host16(h->id) ==
			EVENT_STA_PHY_STATS)
		return 1;
	return 0;
}

static void csm_update_ref_info(csmctx_t *csm, sta_table_t *sta)
{
	sta_assoc_info_t *assoc = &sta->assoc_info;
	sta_seen_bssid_t *seenbssid;

	CSM_LOCK(sta);
	seenbssid = csm_seen_bssid_find_or_add(sta,
		assoc->assoc_mdid, assoc->assoc_bssid);
	if (seenbssid) {
		/* record the ref_* when latest phydrop closest to 50% */
		if (ABS((assoc->supported_phyrate >> 1) - assoc->avg_tx_phyrate)
			< ABS((assoc->supported_phyrate >> 1) - seenbssid->ref_phyrate)) {
			/* average the ref_rssi when phyrate delt varies in (1/32) */
			if (ABS(assoc->avg_tx_phyrate - seenbssid->ref_phyrate)
				< (seenbssid->ref_phyrate >> 5)) {
				seenbssid->ref_rssi <<= 6;
				seenbssid->ref_rssi *= 3;
				seenbssid->ref_rssi += (assoc->avg_rssi << 6);
				seenbssid->ref_rssi >>= 8;
			} else {
				seenbssid->ref_phyrate = assoc->avg_tx_phyrate;
				seenbssid->ref_rssi = assoc->avg_rssi;
			}
		}
	}
	CSM_UNLOCK(sta);
}

static void csm_dump_station_stats(csmctx_t *csm, sta_table_t *sta,
	int tx_phyrate_updated, int rx_phyrate_updated, int rssi_updated)
{
	sta_assoc_info_t *assoc = &sta->assoc_info;
	timestamp_t now = csm_get_timestamp();
	CSM_DEBUG(PPREFIX "[%" MACFMT "] - [%" MACFMT
		"]: last tx/rx: %u/%u(%llu/%llu), rssi: %d; avg tx/rx: %u/%u, rssi %d; pkts %u",
		MACARG(sta->h.mac), MACARG(assoc->assoc_bssid), assoc->last_tx_phyrate,
		assoc->last_rx_phyrate, assoc->last_tx_ts, assoc->last_rx_ts, assoc->last_rssi,
		assoc->avg_tx_phyrate, assoc->avg_rx_phyrate, assoc->avg_rssi, assoc->pkts_per_sec);

	if (!csm->stats_dump.file
		|| csm->stats_dump.lines >= csm->params.statsdump_lines_perfile) {
		char file_name[NAME_MAX];

		if (csm->stats_dump.file) {
			fclose(csm->stats_dump.file);
			csm->stats_dump.file = NULL;
			csm->stats_dump.ind++;
		}
		csm->stats_dump.lines = 0;
		csm->stats_dump.ind %= csm->params.statsdump_files;
		snprintf(file_name, NAME_MAX, "/tmp/associated_sta_stat_%02u", csm->stats_dump.ind);

		csm->stats_dump.file = fopen(file_name, "w");
		if (!csm->stats_dump.file)
			return;

		fprintf(csm->stats_dump.file, "now_ts     sta               bssid            :"
			"   tx,      tx_ts;   rx,      rx_ts; rssi; a_tx; a_rx; a_rssi; pkts\n");
	}

	fprintf(csm->stats_dump.file, "%010" PRIu64 " %" MACFMT " %" MACFMT ": ",
		now, MACARG(sta->h.mac), MACARG(assoc->assoc_bssid));
	if (tx_phyrate_updated)
		fprintf(csm->stats_dump.file, "%04u, %010" PRIu64 "; ",
			assoc->last_tx_phyrate, assoc->last_tx_ts);
	else
		fprintf(csm->stats_dump.file, "----, ----------; ");
	if (rx_phyrate_updated)
		fprintf(csm->stats_dump.file, "%04u, %010" PRIu64 "; ",
			assoc->last_rx_phyrate, assoc->last_rx_ts);
	else
		fprintf(csm->stats_dump.file, "----, ----------; ");
	if (rssi_updated)
		fprintf(csm->stats_dump.file, " %03d; ", assoc->last_rssi);
	else
		fprintf(csm->stats_dump.file, "----; ");
	fprintf(csm->stats_dump.file, "%04u; %04u; %03d;    %04u\n",
		assoc->avg_tx_phyrate, assoc->avg_rx_phyrate,
		assoc->avg_rssi, assoc->pkts_per_sec);

	csm->stats_dump.lines++;
	if (!(csm->stats_dump.lines & 0x0f))
		fflush(csm->stats_dump.file);
}

static void csm_update_station_stats(csmctx_t *csm, sta_table_t *sta)
{
	int tx_phyrate_updated = 0, rx_phyrate_updated = 0, rssi_updated = 0;

	if (!STA_IS_ASSOCIATED(sta))
		return;
	if (sta->assoc_info.last_tx_phyrate)
		tx_phyrate_updated = csm_averager_add_value(sta->tx_phyrate_averager,
			sta->assoc_info.last_tx_phyrate, sta->assoc_info.last_tx_ts);
	if (sta->assoc_info.last_rx_phyrate)
		rx_phyrate_updated = csm_averager_add_value(sta->rx_phyrate_averager,
			sta->assoc_info.last_rx_phyrate, sta->assoc_info.last_rx_ts);

	sta->assoc_info.avg_tx_phyrate =
		csm_averager_get_value(sta->tx_phyrate_averager,
			csm->params.phyrate_avg_age);
	sta->assoc_info.avg_rx_phyrate =
		csm_averager_get_value(sta->rx_phyrate_averager,
			csm->params.phyrate_avg_age);

	rssi_updated = csm_averager_add_value(sta->rssi_averager,
		sta->assoc_info.last_rssi, sta->assoc_info.last_rx_ts);

	sta->assoc_info.avg_rssi =
		csm_averager_get_value(sta->rssi_averager,
			csm->params.rssi_avg_age);

	if (sta->assoc_info.pkts_per_sec != PKTS_PER_SEC_INVALID)
		csm_averager_add_value(sta->pkts_persec_averager,
			sta->assoc_info.pkts_per_sec, 0);

	csm_dump_station_stats(csm, sta,
		tx_phyrate_updated, rx_phyrate_updated, rssi_updated);

	csm_update_ref_info(csm, sta);
}

static void csm_store_history_pkts(sta_table_t *sta,
	uint8_t *data, uint16_t len)
{
	uint32_t pkts = PKTS_PER_SEC_INVALID;

	if (!sta || !data)
		return;

	csm_averager_set_value(sta->pkts_persec_averager, PKTS_PER_SEC_INVALID);
	while (len >= sizeof(uint32_t)) {
		len -= sizeof(uint32_t);
		pkts = extract_host32(data[len]);
		csm_averager_add_value(sta->pkts_persec_averager, pkts, 0);
	}
	sta->assoc_info.pkts_per_sec = pkts;
}

#define STATION_COMM_TX_PRESENT (0x1)
#define STATION_COMM_RX_PRESENT (0x2)
#define CSM_UPDATE_STATION_PHYRATE_TS(present, sta, now)\
	do {\
		if (((present)==STATION_COMM_TX_PRESENT) && (sta)){\
			(sta)->assoc_info.last_tx_ts = (now);\
			SET_FLAG(sta->flag, STATION_FLAG_LEGACY1_STA);\
		}\
		(present) = 0;\
	}while(0)
int csm_decode_station_tlv(csmctx_t * csm, bss_table_t * bss,
			   csmmsgh_t * h)
{
	sta_table_t *sta = NULL;
	tlv_t *t;
	int16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;
	uint16_t type, len;
	int16_t tlen;
	sta_info_t *sta_info = NULL;
	sta_seen_bssid_t *staseenbssid = NULL;
	timestamp_t now = csm_get_timestamp();
	uint8_t msg_from_comm = 0;
	uint8_t tag_filter = 0;
	uint8_t comm_phyrate_present = 0;
	int32_t value32;

	while (payload_len > sizeof(tlv_t)) {
		t = (tlv_t *) payload;
		type = le_to_host16(t->type);
		tlen = csm_tlv_vlen(type);
		len = le_to_host16(t->len);

		if (payload_len < (sizeof(tlv_t) + len))
			break;

		if ((tlen > 0) && (tlen != len)) {
			if ((type != TLVTYPE_TX_PHYRATE_COMM ) || (len != 4))
				CSM_WARNING(PPREFIX "Wrong tlv id=0x%x, len(%d) != vlen(%d)",
				    type, len, tlen);
			goto next;
		}
		if (tag_filter
		    && type != TLVTYPE_STA_MAC)
			goto next;

		switch (type) {
		case TLVTYPE_STA_MAC:
		case TLVTYPE_STA_INFO_COMM:
			if (type == TLVTYPE_STA_MAC)
				msg_from_comm = 0;
			else
				msg_from_comm = 1;

			CSM_UPDATE_STATION_PHYRATE_TS(comm_phyrate_present, sta, now);
			if (sta) {
				CSM_UNLOCK(sta);
				if (!msg_from_comm)
					csm_update_station_stats(csm, sta);
			}
			CSM_REPLACE_OBJ(sta, csm_station_find_or_add
					(csm->station_db, t->value));

			/* In case of:
			 * 1. recevie an not associated current BSS STA_PHY_STATS event;
			 * 2. and this event reported before CONNECT_COMPLETE event.
			 * triger one deauth to remove this non-associated current BSS station. */
			tag_filter = 0;
			if (csm_sta_phy_stats_event_filter(sta, bss, h, type)) {
				tag_filter = 1;
				if (now - sta->assoc_info.last_assoc_ts < 2 * bss->stats_event_period) {
					CSM_DEBUG("Client[% "MACFMT "] is not associated current"
						" BSS[%"MACFMT "] trigger deauth to it",
						MACARG(sta->h.mac), MACARG(bss->h.mac));
					csm_deauth_sta(csm, bss->h.mac, sta->h.mac,
						DEAUTH_CODE_BSS_TRANS);
				}
			}

			if (sta) {
				CSM_LOCK(sta);
				CSM_TOUCH(&sta->h);
			} else
				break;

			if (type == TLVTYPE_STA_INFO_COMM) {
				sta_info = (sta_info_t *) t->value;
				STA_UPDATE_INFO_RXSS(sta, sta_info->rx_ss);
				if (sta_info->band_2g) {
					sta->band_mask |= BIT(BAND_2G);
				}
				if (sta_info->band_5g) {
					sta->band_mask |= BIT(BAND_5G);
				}
			}
			break;
		case TLVTYPE_TX_PHYRATE:
			if (sta) {
				sta->assoc_info.last_tx_phyrate =
				    extract_host32(t->value[0]);
			}
			break;
		case TLVTYPE_TS_LAST_TX:
			if (sta) {
				sta->assoc_info.last_tx_ts =
				    extract_host64(t->value[0]);
			}
			break;
		case TLVTYPE_AGE_LAST_TX:
			if (sta)
				sta->assoc_info.last_tx_ts = now - extract_host64(t->value[0]);
			break;
		case TLVTYPE_RX_PHYRATE:
			if (sta) {
				sta->assoc_info.last_rx_phyrate =
				    extract_host32(t->value[0]);
			}
			break;
		case TLVTYPE_TS_LAST_RX:
			if (sta) {
				sta->assoc_info.last_rx_ts =
				    extract_host64(t->value[0]);
			}
			break;
		case TLVTYPE_AGE_LAST_RX:
			if (sta)
				sta->assoc_info.last_rx_ts = now - extract_host64(t->value[0]);
			break;
		case TLVTYPE_PKT_CNT:
			if (sta)
				sta->assoc_info.pkts_per_sec = extract_host32(t->value[0]);
			break;
		case TLVTYPE_PKT_CNT_HIST:
			if (sta)
				csm_store_history_pkts(sta, t->value, len);
			break;
		case TLVTYPE_CHANNEL_BAND:
			if (msg_from_comm && (sta_info) && !sta_info->associated)
				break;
			if (sta) {
				sta->assoc_info.channel = t->value[0];
				sta->assoc_info.band = t->value[1];
			}
			break;
		case TLVTYPE_RSSI:
			if (msg_from_comm && (sta_info) && !sta_info->associated)
				break;
			if (sta) {
				value32 = extract_host32(t->value[0]);
				sta_seen_bssid_t *staseenbssid_local;

				if (0 == value32)
					break;
				if ((bss)
				    && IS_ASSOCIATED_WITH(sta, bss->h.mac)
				    && (le_to_host16(h->id) ==
					EVENT_NONASSOC_STA_PHY_STATS)) {
					break;
				}

				if (IS_ASSOCIATED_WITH(sta, h->bssid))
					sta->assoc_info.last_rssi = value32;
				if (bss) {
					sta->band_mask |= BIT(bss->band);
					sta->last_band = bss->band;
					sta->last_channel = bss->channel;
					staseenbssid_local =
					    csm_seen_bssid_find_or_add(sta,
								       bss->mdid,
								       bss->h.mac);
					if (staseenbssid_local) {
						staseenbssid_local->last_ts
						    = now;
						staseenbssid_local->last_rssi
						    = value32;
						STA_UPDATE_RSSI_TS(sta,
								   now);
					}
				} else if (staseenbssid) {
					staseenbssid->last_ts = now;
					staseenbssid->last_rssi = value32;
					STA_UPDATE_RSSI_TS(sta, now);
				}

			}
			break;
		case TLVTYPE_MAC_MDID:
			if (!sta)
				break;
			if ((msg_from_comm) && (sta_info)){
				if(!sta_info->associated) {
					csm_sta_update_supported_capability(sta, sta_info->capability, 0);
					break;
				} else {
					csm_sta_update_supported_capability(sta, sta_info->capability, 1);
				}
			}
			STA_UPDATE_ASSOC_BSS(sta, t->value, t->value + ETH_ALEN);
			break;
		/* same caes id: TLVTYPE_TX_PHYRATE_BW */
		case TLVTYPE_SUPPORTED_PHYRATE_COMM:
			if ((!sta) || (!sta_info) || (!sta_info->associated))
				break;

			if (msg_from_comm)
				sta->assoc_info.supported_phyrate =
					extract_host32(t->value[0]);
			else
				sta->assoc_info.last_tx_bandwidth = extract_host16(t->value[2]);
		break;
		case TLVTYPE_RX_PHYRATE_BW:
			if ((msg_from_comm) || (!sta) || (!sta_info) || (!sta_info->associated))
				break;

			sta->assoc_info.last_rx_bandwidth = extract_host16(t->value[2]);
			break;
		/* same case id: TLVTYPE_AVG_STA_AIRTIME(from RPE) = 512 */
		case TLVTYPE_TX_PHYRATE_COMM:
			if (!sta)
				break;
			if (msg_from_comm) {
				if (!sta_info->associated)
					break;
				sta->assoc_info.last_tx_ts =
				    now - extract_host32(t->value[0]);
				sta->assoc_info.avg_tx_phyrate =
				    extract_host32(t->value[4]);
				SET_FLAG(comm_phyrate_present, STATION_COMM_TX_PRESENT);
			} else { /* case TLVTYPE_AVG_STA_SIRTIME */
				sta->assoc_info.avg_airtime =
					extract_host32(t->value[0]);
			}
			break;
		case TLVTYPE_RX_PHYRATE_COMM:
			if (!sta)
				break;
			if (msg_from_comm && !sta_info->associated)
				break;
			sta->assoc_info.last_rx_ts =
			    now - extract_host32(t->value[0]);
			sta->assoc_info.avg_rx_phyrate =
			    extract_host32(t->value[4]);
			SET_FLAG(comm_phyrate_present, STATION_COMM_RX_PRESENT);
			break;
		case TLVTYPE_SEEN_BY_COMM:
			if (!sta) {
				staseenbssid = NULL;
				break;
			}
			staseenbssid =
			    csm_seen_bssid_find_or_add(sta,
						       t->value + ETH_ALEN,
						       t->value);
			break;
		case TLVTYPE_REFERENCE:
			if (!staseenbssid)
				break;
			staseenbssid->ref_rssi = (int16_t)(extract_host16(t->value[0]));
			staseenbssid->ref_phyrate = extract_host16(t->value[2]);
			break;
		case TLVTYPE_STA_RSSI_COMM:
			if (!staseenbssid)
				break;
			value32 = extract_host32(t->value[4]);
			if (value32) {
				staseenbssid->last_ts =
				    now - extract_host32(t->value[0]);
				staseenbssid->last_rssi = value32;
				STA_UPDATE_RSSI_TS(sta, staseenbssid->last_ts);
				if ((sta)
				    && IS_ASSOCIATED_WITH(sta,
							  staseenbssid->bssid)) {
					sta->assoc_info.last_rssi = value32;
					sta->assoc_info.avg_rssi = value32;
				}
			}
			break;
		case TLVTYPE_IES_COMM:
			if (sta) {
				struct frame_ctx fctx;
				bss_table_t *cur = csm_bss_find(csm->bss_db, sta->assoc_info.assoc_bssid);
				if (!cur)
					break;

				fctx.csm = csm;
				fctx.bss = cur;
				fctx.sta = sta;
				csm_process_frame(0, t->value, len,
					&fctx, NULL, csm_process_assoc_req_ie);

				if (cur)
					csm_bss_put(cur);
			}
			break;
		case TLVTYPE_NODE_TYPE:
			if (sta) {
				value32 = extract_host32(t->value);
				if (value32 != NODE_TYPE_UNKNOW && value32 <= NODE_TYPE_NOTWIFI)
					sta->node_type = value32;
			}
			break;
		case TLVTYPE_LINK_STATS:
			if (sta && len >= sizeof(sta->assoc_info.stats)) {
				sta->assoc_info.stats.tx_packets = extract_host32(t->value[4 * 0]);
				sta->assoc_info.stats.tx_bytes = extract_host32(t->value[4 * 1]);
				sta->assoc_info.stats.rx_packets = extract_host32(t->value[4 * 2]);
				sta->assoc_info.stats.rx_bytes = extract_host32(t->value[4 * 3]);
				sta->assoc_info.stats.tx_errors = extract_host32(t->value[4 * 4]);
				sta->assoc_info.stats.rx_errors = extract_host32(t->value[4 * 5]);
				sta->assoc_info.stats.tx_tries = extract_host32(t->value[4 * 6]);
			}
			break;
		default:
			break;

		}
	      next:
		payload += (sizeof(tlv_t) + CSM_IE_LEN(len));
		payload_len -= (sizeof(tlv_t) + CSM_IE_LEN(len));
	};
	CSM_UPDATE_STATION_PHYRATE_TS(comm_phyrate_present, sta, now);
	if (sta) {
		CSM_UNLOCK(sta);
		if (!msg_from_comm)
			csm_update_station_stats(csm, sta);
		csm_station_put(sta);
	}

	if (payload_len != 0)
		CSM_WARNING(PPREFIX "extra payload(%d) in event(%u)",
			    payload_len, le_to_host16(h->id));

	return 0;
}

static void csm_update_bss_capability(bss_table_t * bss)
{
	sta_cap_t cap;
	uint8_t ht_ss = 1, vht_ss = 1;

	cap.cap = 0;

	if ((bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_VHT
		|| bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_HT)
		&& check_ht_operation_ie(bss->ht_operation)
		&& check_ht_capabilities_ie(bss->ht_capability)) {
		struct ieee80211_ie_htinfo *htinfo =
			(struct ieee80211_ie_htinfo *)(bss->ht_operation);
		cap.ht_supported = 1;
		/* ht bandwidth */
		cap.cap |= ((htinfo->bytes[0] & IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40)
			>> IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40_SHIFT);

		ht_ss = get_bss_txss_from_ht_capabilities(bss->ht_capability);
	}
	if (bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_VHT
		&& check_vht_operation_ie(bss->vht_operation)
		&& check_vht_capabilities_ie(bss->vht_capability)) {
		struct ieee80211_ie_vhtop *vhtop =
			(struct ieee80211_ie_vhtop *)(bss->vht_operation);
		struct ieee80211_ie_vhtcap *vhtcap =
			(struct ieee80211_ie_vhtcap *)(bss->vht_capability);
		cap.vht_supported = 1;
		cap.cap |= ((vhtop->info[0] & 0x3) << 1);
		cap.cap |= (((vhtcap->cap[2] & IEEE80211_VHTCAP_C_MU_BEAM_CAP)
			>> IEEE80211_VHTCAP_C_MU_BEAM_CAP_SHIFT) << 5);

		vht_ss = get_bss_txss_from_vht_capabilities(bss->vht_capability);
	}
	if (bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_BTM)
		cap.bss_transition_supported = 1;

	bss->bss_capability = cap;
	bss->txss = vht_ss > ht_ss ? vht_ss : ht_ss;
}

static inline uint16_t csm_get_radio_1905_iftype(bss_table_t *bss)
{
	if (check_he_capabilities_ie(bss->he_capability)) {
		return IFTYPE_1905_11AX;
	}
	if (bss->bss_capability.vht_supported)
		return IFTYPE_1905_11AC_5G;
	if (bss->bss_capability.ht_supported) {
		if (bss->band == BAND_5G)
			return IFTYPE_1905_11N_5G;
		else
			return IFTYPE_1905_11N_2G;
	}
	if (bss->band == BAND_5G)
		return IFTYPE_1905_11A;
	if (bss->phy_type == DOT11_PHY_TYPE_ERP)
		return IFTYPE_1905_11G;
	return IFTYPE_1905_11B;
}

static void csm_update_radio_info_from_bss(bss_table_t *bss)
{
	radio_table_t *radio;
	if (!bss || !bss->radio)
		return;
	radio = bss->radio;
	radio->fat = bss->fat;
	radio->latest_fat_ts = bss->last_fat;
	radio->opclass = bss->operation_class;
	radio->chan = bss->channel;
	radio->tx_power_backoff = bss->tx_power_backoff;

	radio->iftype_1905 = csm_get_radio_1905_iftype(bss);
}

static int csm_check_registrable_frames_valid(bss_table_t *bss,
	uint8_t *frm, uint16_t len, int is_rx)
{
	uint8_t *pos = frm, *efrm = frm + len;
	while (pos + 1 + 1 + 1	/* subtype + handing + matchlen */
		<= efrm) {
		pos += (3 + pos[2]);
	}

	if (pos != efrm) {
		CSM_WARNING(PPREFIX "%" MACFMT " %s frames registrable tlv is wrong\n",
			MACARG(bss->h.mac), is_rx ? "rx" : "tx");
		return 0;
	}
	return 1;
}

static void csm_update_registrable_frames(csmctx_t *csm,
	bss_table_t *bss, uint8_t *frm, uint16_t len, int is_rx)
{
	uint8_t *pos = frm, *efrm = frm + len;

	if (!csm_check_registrable_frames_valid(bss, frm, len, is_rx))
		return;

	while (pos + 3 <= efrm
		&& pos + 3 + pos[2] <= efrm) {
		csm_update_registrable_frame(csm, bss, is_rx,
			pos[0], pos + 3, pos[2]);
		pos += (3 + pos[2]);
	}
}

static inline void csm_update_ac_espi(espi_t *espi,
	uint8_t format, uint8_t window, uint8_t duration)
{
	espi->valid = 1;
	espi->format = format;
	espi->window = window;
	espi->duration = duration;
}

static void csm_check_and_store_espi_from_tlv(bss_table_t *bss,
	uint8_t *val, uint16_t len)
{
	uint16_t i;

	if (!bss)
		return;
	if (len % 4) {
		CSM_ERROR("ESPI field len (%u) is wrong", len);
		return;
	}

	/* should reset the espi? */
	for (i = 0; i < AC_MAXNUM; i++)
		bss->espis[i].valid = 0;

	for (i = 0; i < len; i += 4) {
		if (0xff == val[i]) {
			csm_update_ac_espi(&bss->espis[0],
				val[i + 1], val[i + 2], val[i + 3]);
			csm_update_ac_espi(&bss->espis[1],
				val[i + 1], val[i + 2], val[i + 3]);
			csm_update_ac_espi(&bss->espis[2],
				val[i + 1], val[i + 2], val[i + 3]);
			csm_update_ac_espi(&bss->espis[3],
				val[i + 1], val[i + 2], val[i + 3]);
		} else if (val[i] < AC_MAXNUM) {
			csm_update_ac_espi(&bss->espis[val[i]],
				val[i + 1], val[i + 2], val[i + 3]);
		}
	}
}

int csm_decode_bss_tlv(csmctx_t * csm, bss_table_t * bss, uint8_t *device_id,
		       csmmsgh_t * h, csmpluginctx_t * ctx)
{
	tlv_t *t;
	int16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;
	uint16_t type, len;
	int16_t tlen;
	uint8_t mdid[MDID_LEN];
	int update = 0;

	if (bss) {
		CSM_LOCK(&bss->h);
		CSM_TOUCH(&bss->h);
	}

	while (payload_len > sizeof(tlv_t)) {
		t = (tlv_t *) payload;
		type = le_to_host16(t->type);
		tlen = csm_tlv_vlen(type);
		len = le_to_host16(t->len);

		if (payload_len < (sizeof(tlv_t) + len))
			break;

		if ((tlen > 0) && (tlen != len)) {
			CSM_WARNING(PPREFIX "Wrong tlv id=0x%x, len(%d) != vlen(%d)",
				    type, len, tlen);
			goto next;
		}

		switch (type) {
		case TLVTYPE_MAC_MDID:
			{
				if (h->api_ver >= CSM_VER_2) {
					COPYMDID(mdid, &t->value[6]);
				} else {
					COPYMDID(mdid, default_mdid);
				}
				if (bss) {
					if (update) {
						csm_update_bss_capability(bss);
						update = 0;
					}
					csm_update_radio_info_from_bss(bss);
					CSM_UNLOCK(bss);
				}
				CSM_REPLACE_OBJ(bss,
						csm_bss_find_or_add
						(csm->bss_db, device_id,
						 t->value, ctx));

				if (bss) {
					csm_hessid_update(csm, bss->mdid, mdid, bss->h.mac, ctx);
					COPYMDID(bss->mdid, mdid);
					memcpy(bss->mdid, mdid, MDID_LEN);
					if (bss->iftype == NODE_TYPE_VAP)
						COPYMAC(bss->bssid, bss->h.mac);
					if (bss->h.age == 0)
						CSM_DEBUG("BSS[%"
							  MACFMT
							  "] created.",
							  MACARG
							  (bss->
							   h.mac));

					bss->md = csm_find_mobility_domain(csm, mdid);
					CSM_LOCK(&bss->h);
					CSM_TOUCH(&bss->h);
				}
			}
			break;
		case TLVTYPE_CHANNEL_BAND:
			if (bss) {
				bss->channel = t->value[0];
				bss->band = t->value[1];
				bss->operation_class = t->value[2];
				/* TODO: how to get operation class for RTL which not support MBO now */
				if (BAND_2G == bss->band)
					bss->operation_class = 81;
			}
			break;
		case TLVTYPE_CHANNEL_BAND_CC:
			if (bss) {
				bss->channel = t->value[0];
				memcpy(bss->country_code, t->value + 2, 2);
				bss->operation_class = csm_get_global_opclass(bss->country_code,
					t->value[1]);
				bss->band = csm_channel_to_band(bss->channel);
			}
			break;
		case TLVTYPE_INTERFACE_CAPABILITY:
			if (bss) {
				bss->driver_cap = t->value[0];
				bss->phy_type = t->value[1];
				memcpy
				    (bss->capabilities_infomation,
				     &t->value[2], 2);
				update = 1;
			}
			break;
		case TLVTYPE_HT_CAPABILITY:
			if (bss) {
				memcpy(bss->ht_capability,
				       t->value, HT_CAPABILITY_LEN);
				update = 1;
			}
			break;
		case TLVTYPE_HT_OPERATION:
			if (bss) {
				memcpy(bss->ht_operation,
				       t->value, HT_OPERATION_LEN);
				update = 1;
			}
			break;
		case TLVTYPE_VHT_CAPABILITY:
			if (bss) {
				memcpy(bss->vht_capability,
				       t->value, VHT_CAPABILITY_LEN);
				update = 1;
			}
			break;
		case TLVTYPE_VHT_OPERATION:
			if (bss) {
				memcpy(bss->vht_operation,
				       t->value, VHT_OPERATION_LEN);
				update = 1;
			}
			break;
		case TLVTYPE_HE_CAPABILITY:
			if (bss && (len >= 2 + t->value[1])
				&& check_he_capabilities_ie(t->value))
				memcpy(bss->he_capability, t->value, len);
			break;
		case TLVTYPE_HE_OPERATION:
			if (bss && (len >= 2 + t->value[1])
				&& check_he_operation_ie(t->value))
				memcpy(bss->he_operation, t->value, len);
			break;
		case TLVTYPE_AVERAGE_FAT:
			if (bss) {
				uint16_t value;
				bss->channel = t->value[0];
				bss->band = t->value[1];
				value = extract_host16(t->value[2]);
				if (value == 0)
					value = 1000;
				bss->fat = value;
				bss->last_fat = csm_get_timestamp();
			}
			break;
		case TLVTYPE_AVG_FAT_COMM:
			/* TODO: need cc from bss for getting global opclass for STA */
			if (bss) {
				uint16_t value;
				bss->channel = t->value[0];
				if (bss->channel > 14)
					bss->band = BAND_5G;
				else
					bss->band = BAND_2G;
				bss->operation_class = t->value[1];
				value = extract_host16(t->value[2]);
				if (value == 0)
					value = 1000;
				bss->fat = value;
				bss->last_fat = csm_get_timestamp();
			}
			break;
		case TLVTYPE_BSS_STATUS_COMM:
			if (bss) {
				uint16_t bss_status;
				bss_status = extract_host16(t->value[0]);
				if (!BSS_IS_UP(bss)) {
					if (bss_status == RPE_INTF_STATE_UP) {
						CSM_WARNING(PPREFIX "bss status isn't consistency, update it");
						BSS_SET_UP(bss);
					}
				} else if (bss_status != RPE_INTF_STATE_UP) {
					CSM_WARNING(PPREFIX "bss status isn't consistency, update it");
					BSS_SET_DOWN(bss);
				}
			}
			break;
		case TLVTYPE_INTERFACE_FEAT_COMM:
			if (bss) {
				uint32_t feat = extract_host32(t->value[0]);
				bss->flag &= ~(BSS_FLAG_MBO | BSS_FLAG_ACR);
				bss->flag |= feat & (BSS_FLAG_MBO | BSS_FLAG_ACR);
			}
			break;
		case TLVTYPE_IFNAME:
			if (bss) {
				if (strlen((char *)(t->value)) <= IFNAMSIZ) {
					strcpy(bss->ifname, (char *)(t->value));
				}
			}
			break;
		case TLVTYPE_SSID:
			if (bss) {
				bss->ssid_len = len;
				if (bss->ssid_len > IEEE80211_SSID_MAXLEN)
					bss->ssid_len = IEEE80211_SSID_MAXLEN;
				COPYMEM(bss->ssid, t->value, bss->ssid_len);
				bss->ssid[bss->ssid_len] = '\0';
			}
			break;
		case TLVTYPE_BEACON_INTERVAL:
			if (bss) {
				bss->binterval =
				    extract_host16(t->value[0]);
			}
			break;
		case TLVTYPE_BACKBONE_INFO:
			if (bss) {
				csm_update_uplink_sta_type(csm, t->value,
					bss->backbone_info.uplink_local);
				COPYMAC(bss->backbone_info.uplink_local, t->value);
				bss->backbone_info.backbone_type = t->value[ETH_ALEN];
			}
			break;
		case TLVTYPE_SPDIA_SUPPORTED_FEATURES:
			if (bss) {
				bss->spdia_supported_feature = t->value[0];
			}
			break;
		case TLVTYPE_SPDIA_CAPABILITIES:
			if (bss) {
				bss->spdia_sta_support_count = t->value[0];
			}
			break;
		case TLVTYPE_IE_EDIT_ALLOWED:
			if (bss) {
				if (len > SUPP_EID_MASK_BYTES) {
					CSM_WARNING(PPREFIX "extra edit ie allowed len(%u)",
						len);
					len = SUPP_EID_MASK_BYTES;
				}
				memcpy(&(bss->supp_elemid_mask[0]),
						&(t->value[0]), len);
			}
			break;
		case TLVTYPE_EXTCAP_EDIT_ALLOWED:
			if (bss) {
				if (len > SUPP_EXTCAP_MASK_BYTES) {
					CSM_WARNING(PPREFIX "supported extcap ie allowed len(%u) is over",
						len);
					len = SUPP_EXTCAP_MASK_BYTES;
				}
				memcpy(bss->supp_extcap_mask, t->value, len);
			}
			break;
		case TLVTYPE_EXT_INTF_CAPABILITY:
			if (bss)
				bss->ext_cap =
				    extract_host32(t->value[0]);
			break;
		case TLVTYPE_REG_MGMT_FRAME_TX:
			if (bss) {
				csm_update_registrable_frames(csm, bss, t->value, len, 0);
				bss->registrable_tx_frm_len = len;
				if (len > REG_FRAME_MAXLEN) {
					bss->registrable_tx_frm_len = REG_FRAME_MAXLEN;
					CSM_WARNING(PPREFIX "extra tx reg frame len(%u)",
						len);
				}
				memcpy(bss->registrable_tx_frm,
					t->value, bss->registrable_tx_frm_len);
			}
			break;
		case TLVTYPE_REG_MGMT_FRAME_RX:
			if (bss) {
				csm_update_registrable_frames(csm, bss, t->value, len, 1);
				bss->registrable_rx_frm_len = len;
				if (len > REG_FRAME_MAXLEN) {
					bss->registrable_rx_frm_len = REG_FRAME_MAXLEN;
					CSM_WARNING(PPREFIX "extra rx reg frame len(%u)",
						len);
				}
				memcpy(bss->registrable_rx_frm,
					t->value, bss->registrable_rx_frm_len);
			}
			break;
		case TLVTYPE_TX_POWER_BACKOFF:
			if (bss)
				bss->tx_power_backoff = t->value[0];
			break;
		case TLVTYPE_RADIO_MAC:
			csm_update_bss_into_radio(csm, bss, t->value);
			break;
		case TLVTYPE_BSSID:
			if (bss)
				COPYMAC(bss->bssid, t->value);
			break;

		case TLVTYPE_NODE_TYPE:
			if (bss) {
				bss->iftype = extract_host32(t->value[0]);
				if (bss->iftype == NODE_TYPE_VAP)
					COPYMAC(bss->bssid, bss->h.mac);
			}
			break;

		case TLVTYPE_ESPI:
			csm_check_and_store_espi_from_tlv(bss, t->value, len);
			break;

		default:
			break;

		}
	      next:
		payload += (sizeof(tlv_t) + CSM_IE_LEN(len));
		payload_len -= (sizeof(tlv_t) + CSM_IE_LEN(len));
	};

	if (bss) {
		if (update)
			csm_update_bss_capability(bss);
		csm_update_radio_info_from_bss(bss);
		CSM_UNLOCK(bss);
		csm_bss_put(bss);
	}

	if (payload_len != 0)
		CSM_WARNING(PPREFIX "extra payload(%d) in event(%u)",
			    payload_len, le_to_host16(h->id));

	return 0;
}

void csm_process_intf_status(csmctx_t *csm, bss_table_t *bss, uint32_t status)
{
	if (!bss)
		return;

	switch (status) {
	case RPE_INTF_STATE_UP:
		BSS_SET_UP(bss);
		CSM_NOTICE(PPREFIX "BSS[%" MACFMT "] is up.",
			MACARG(bss->h.mac));
		break;
	case RPE_INTF_STATE_DOWN:
	case RPE_INTF_STATE_NONAVAILABLE:
		BSS_SET_DOWN(bss);
		CSM_NOTICE(PPREFIX "BSS[%" MACFMT "] is %s.",
			MACARG(bss->h.mac), status == RPE_INTF_STATE_DOWN ? "down" : "nonavail");
		break;
	case RPE_INTF_STATE_DELETED:
		CSM_NOTICE(PPREFIX "BSS[%" MACFMT "] is deleted.",
			MACARG(bss->h.mac));
		break;
	default:
		CSM_ERROR(PPREFIX "Unkown state = %d for BSS.",
			status);
		break;
	}
}

static int
csm_process_event_intf_status(csmctx_t * csm, csmmsgh_t * h,
			      bss_table_t * bss, drvctx_t * drv)
{

	uint32_t status = le_to_host32(((evt_intf_status_t *)h)->status);

	csm_process_intf_status(csm, bss, status);

	if (bss)
		csm_bss_put(bss);
	return 0;
}

static int
csm_process_event_intf_info(csmctx_t * csm, csmmsgh_t * h,
			    bss_table_t * bss, drvctx_t * drv)
{
	int ret;
	ret = csm_decode_bss_tlv(csm, bss, NULL, h, (csmpluginctx_t *) drv);
	return ret;
}

#if 0
static bw_e csm_station_get_max_bandwidth_from_sta_capability(sta_cap_t *
							      cap)
{
	if (cap->vht_supported) {
		return (cap->vht_bw ? BW_160M : BW_80M);
	} else {
		return (cap->ht_bw ? BW_40M : BW_20M);
	}
}
#endif

static int
csm_process_event_probe_req(csmctx_t * csm, csmmsgh_t * h,
			    bss_table_t * bss, drvctx_t * drv)
{
	evt_probe_req_t *ep = (evt_probe_req_t *) h;
	sta_table_t *sta;
	sta_seen_bssid_t *staseenbssid;
	int32_t rssi;
	if (bss) {
		sta =
		    csm_station_find_or_add(csm->station_db, ep->sta_mac);
		if (sta) {
			uint16_t band = le_to_host16(ep->curr_band);
			sta_band_info_t *sbinfo;
			if (sta->h.age == 0)
				CSM_DEBUG("Client[%" MACFMT "] created.",
					  MACARG(sta->h.mac));
			CSM_LOCK(sta);
			CSM_TOUCH(&sta->h);

			/* cause rpe event not update ht_supported, infer and update it from vht/ht_bw/max_phyrate */
			csm_sta_infer_and_update_ht_supported(&ep->capability, le_to_host16(ep->max_phyrate));
			csm_sta_update_supported_capability(sta, ep->capability, 0);

			sbinfo = &sta->sta_band_info[band];
			sta->last_band = band;
			sta->last_channel = ep->channel;
			sta->band_mask |= BIT(band);
			sbinfo->flag |= BAND_INFO_FLAG_VALID;
			sbinfo->supported_phyrate =
			    le_to_host16(ep->max_phyrate);
			sbinfo->capability.cap = ep->capability;

			staseenbssid =
			    csm_seen_bssid_find_or_add(sta, bss->mdid,
						       bss->h.mac);
			rssi = le_to_host32(ep->rssi);
			if (staseenbssid && rssi) {
				staseenbssid->last_ts = csm_get_timestamp();
				staseenbssid->ch = bss->channel;
				staseenbssid->last_rssi = rssi;
				STA_UPDATE_RSSI_TS(sta,
						   staseenbssid->last_ts);
			}
			CSM_UNLOCK(sta);
			csm_station_put(sta);
		}

		csm_bss_put(bss);

	} else {
		CSM_WARNING(PPREFIX "%s:bss %" MACFMT " not found.", __FUNCTION__, MACARG(h->bssid));
	}

	return 0;
}

static void csm_correct_assoc_supported_phyrate(sta_table_t *sta,
	bss_table_t *bss)
{
	uint32_t bss_supported_phyrate =
		csm_get_bss_supported_maxphyrate(bss);
	if (sta->assoc_info.supported_phyrate > bss_supported_phyrate) {
		CSM_WARNING(PPREFIX "update sta %" MACFMT
			" supported phyrate(%u-->%u) with bss %" MACFMT,
			MACARG(sta->h.mac), sta->assoc_info.supported_phyrate,
			bss_supported_phyrate, MACARG(bss->h.mac));
		sta->assoc_info.supported_phyrate = bss_supported_phyrate;
	}
}

static void csm_reset_sta_assoc_info(sta_table_t *sta)
{
	csm_averager_set_value(sta->tx_phyrate_averager, 0);
	csm_averager_set_value(sta->rx_phyrate_averager, 0);
	csm_averager_set_value(sta->rssi_averager, 0);
	csm_averager_set_value(sta->pkts_persec_averager, PKTS_PER_SEC_INVALID);
	sta->assoc_info.avg_tx_phyrate = 0;
	sta->assoc_info.avg_rx_phyrate = 0;
	sta->assoc_info.avg_rssi = 0;
	sta->assoc_info.pkts_per_sec = PKTS_PER_SEC_INVALID;

	memset(&sta->assoc_info.stats, 0, sizeof(sta->assoc_info.stats));
}

static int csm_check_connect_complete_value(evt_connect_complete_t *ec)
{
	uint8_t band;
	if (ec->h.api_ver >= 4)
		band = ec->node_bype_band.curr_band_v4;
	else
		band = (uint8_t)le_to_host16(ec->node_bype_band.curr_band);

	if (band >= BAND_MAX) {
		CSM_ERROR("Connect complete: the band field value (%u) is over\n", band);
		return -1;
	}
	/* TODO: check other fields */
	return 0;
}

static void csm_update_node_type_by_backbone_info(csmctx_t *csm,
	sta_table_t *sta)
{
	int i;
	struct sta_sdb *db = csm->bss_db;
	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah;
		list_for_each_entry(stah, &db->stalh[i], lh) {
			bss_table_t *bss = (bss_table_t *)stah;
			if (MACADDR_EQ(sta->h.mac,
				bss->backbone_info.uplink_local)) {
				CSM_INFO("update %" MACFMT " to repeater", MACARG(sta->h.mac));
				sta->node_type = NODE_TYPE_REPEATER;
				goto __end;
			}
		}
	}
__end:
	CSM_UNLOCK(db);
}

static int
csm_process_event_connect_complete(csmctx_t * csm, csmmsgh_t * h,
				   bss_table_t * bss, drvctx_t * drv)
{
	evt_connect_complete_t *ec = (evt_connect_complete_t *) h;
	sta_table_t *sta;
	sta_seen_bssid_t *staseenbssid;

	if (bss == NULL) {
		CSM_WARNING("BSS not found when client associated.");
		goto bail;
	}
	if (csm_check_connect_complete_value(ec) < 0)
		goto bail;
	if (0 == memcmp(h->bssid, ec->sta_mac, ETH_ALEN)) {
		CSM_WARNING("the bssid && sta_mac are same=["MACFMT"] in EVT_CON_CMPT",
				MACARG(ec->sta_mac));
		goto bail;
	}

	sta = csm_station_find_or_add(csm->station_db, ec->sta_mac);

	if (sta) {
		sta_band_info_t *sbinfo;
		uint8_t curr_band, node_type;

		csm_reset_sta_assoc_info(sta);

		if (h->api_ver >= 4) {
			curr_band = ec->node_bype_band.curr_band_v4;
			node_type = ec->node_bype_band.node_type;
		} else {
			curr_band = (uint8_t)le_to_host16(ec->node_bype_band.curr_band);
			node_type = NODE_TYPE_STA;
		}
		CSM_LOCK(sta);
		CSM_TOUCH(&sta->h);
		sbinfo = &sta->sta_band_info[curr_band];
		sta->node_type = node_type;
		sta->last_band = curr_band;
		sta->last_channel = ec->channel;
		sta->band_mask |= BIT(curr_band);

		STA_UPDATE_INFO_RXSS(sta, le_to_host16(ec->rx_ss));
		/* cause rpe event not update ht_supported, infer and update it from vht/ht_bw/max_phyrate */
		csm_sta_infer_and_update_ht_supported(&ec->capability, le_to_host16(ec->max_phyrate));
		csm_sta_update_supported_capability(sta, ec->capability, 1);
		
		STA_UPDATE_BANDINFO_RXSS(sta, sbinfo,
					 le_to_host16(ec->rx_ss));
		sbinfo->flag |= BAND_INFO_FLAG_VALID;
		sbinfo->supported_phyrate = le_to_host16(ec->max_phyrate);
		sbinfo->capability.cap = ec->capability;

		sta->assoc_info.last_assoc_ts = csm_get_timestamp();
		sta->assoc_info.supported_phyrate =
		    le_to_host16(ec->max_phyrate);
		sta->assoc_info.channel = ec->channel;
		sta->assoc_info.band = curr_band;
		STA_UPDATE_ASSOC_BSS(sta, h->bssid, bss->mdid);

		csm_correct_assoc_supported_phyrate(sta, bss);
		csm_update_node_type_by_backbone_info(csm, sta);

		/* to ensure the current bss is in the seenlist,
		 * add one with rssi 0 if not found, cause this event not carry any rssi;
		 * fixing for: The associated sta reported by RTL will be delete when restart the daemon with the QTN interface down */
		staseenbssid =
		    csm_seen_bssid_find_or_add(sta, bss->mdid,
					       bss->h.mac);
		if (staseenbssid && staseenbssid->last_rssi == 0) {
			staseenbssid->last_ts = csm_get_timestamp();
			STA_UPDATE_RSSI_TS(sta,
					   staseenbssid->last_ts);
		}

		CSM_UNLOCK(sta);

		csm_station_put(sta);
	}

bail:
	if (bss)
		csm_bss_put(bss);
	return 0;
}

static int
csm_process_event_deauth(csmctx_t * csm, csmmsgh_t * h, bss_table_t * bss,
			 drvctx_t * drv)
{
	return csm_process_event_disassoc(csm, h, bss, drv);
}

static int
csm_process_event_disassoc(csmctx_t * csm, csmmsgh_t * h,
			   bss_table_t * bss, drvctx_t * drv)
{
	evt_disassoc_t *ed = (evt_disassoc_t *) h;
	sta_table_t *sta;
	sta = csm_station_find(csm->station_db, ed->sta_mac);
	uint16_t reason_code = le_to_host16(ed->reason_code);

	if (sta) {
		CSM_LOCK(sta);
		CSM_TOUCH(&sta->h);
		CSM_INFO(PPREFIX "%" MACFMT
			 " deassociated, reason code = %d",
			 MACARG(ed->sta_mac), reason_code);
		STA_UPDATE_DISASSOCIATATION_BSSID(sta, h->bssid);
		if (sta->assoc_info.latest_assoc) {
			CSM_FREE(sta->assoc_info.latest_assoc);
			sta->assoc_info.latest_assoc = NULL;
		}
		sta->assoc_info.latest_assoc_len = 0;
		CSM_UNLOCK(sta);
		csm_station_put(sta);
	} else {
		CSM_WARNING(PPREFIX "Station[%" MACFMT
			    "] disassocation but not found in database, reason code=%d",
			    MACARG(ed->sta_mac), reason_code);
	}

	if (bss)
		csm_bss_put(bss);
	return 0;
}

static int
csm_process_event_sta_phy_stats(csmctx_t * csm, csmmsgh_t * h,
				bss_table_t * bss, drvctx_t * drv)
{
	int ret;

	ret = csm_decode_station_tlv(csm, bss, h);
	if (bss)
		csm_bss_put(bss);

	return ret;
}

static int
csm_process_event_bss_trans_status(csmctx_t * csm, csmmsgh_t * h,
				   bss_table_t * bss, drvctx_t * drv)
{
	evt_bss_trans_status_t *btm_status = (evt_bss_trans_status_t *) h;
	CSM_INFO(PPREFIX "Get btm status=%d for Client[%" MACFMT "]",
		 le_to_host16(btm_status->status_code),
		 MACARG(btm_status->sta_mac));
	if (bss)
		csm_bss_put(bss);
	return 0;
}

static void
csm_parse_and_process_sta_tlv(csmctx_t *csm, csmmsgh_t *h,
		bss_table_t *bss, process_sta_func_t process_cb)
{
	tlv_t *t;
	int16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;
	uint16_t type, len;
	int16_t tlen;
	sta_parse_stats_t stats;
	int8_t start = 0;

	if (!process_cb)
		return;

	while (payload_len > sizeof(tlv_t)) {
		t = (tlv_t *) payload;
		type = le_to_host16(t->type);
		tlen = csm_tlv_vlen(type);
		len = le_to_host16(t->len);

		if (payload_len < (sizeof(tlv_t) + len))
			break;

		if ((tlen > 0) && (tlen != len)) {
			CSM_WARNING(PPREFIX "Wrong tlv id=0x%x, len(%d) != vlen(%d)",
				    type, len, tlen);
			goto next;
		}
		switch (type) {
		case TLVTYPE_STA_MAC:
			if (start)
				process_cb(csm, bss, &stats);
			else
				start = 1;
			memset(&stats, 0, sizeof(stats));
			stats.mac = payload;
			break;

		case TLVTYPE_RSSI:
			stats.rssi = payload;
			break;

		case TLVTYPE_RSSI_ADV:
			stats.adv_rssi = payload;
			break;

		case TLVTYPE_TS_LAST_RX:
			stats.ts_last_rx = payload;
			break;

		case TLVTYPE_AGE_LAST_RX:
			stats.age_last_rx = payload;
			break;

		/* only for non-assoc sta stats just now
		 * expend other case, when using for other event(eg: assoc sta stats/sta stats from comm */
		default:
			break;
		}

next:
		payload += (sizeof(tlv_t) + len);
		payload_len -= (sizeof(tlv_t) + len);
	}

	if (start)
		process_cb(csm, bss, &stats);

	if (payload_len != 0)
		CSM_WARNING(PPREFIX "extra payload(%d) in event(%u)",
			    payload_len, le_to_host16(h->id));
}

static void
csm_update_nonassoc_sta_stats(csmctx_t *csm, bss_table_t *bss, sta_parse_stats_t *stats)
{
	timestamp_t ts;
	sta_table_t *sta = NULL;
	sta_seen_bssid_t *seenbssid = NULL;
	uint64_t age;

	if (!bss)
		return;

	if (!stats->mac
		|| !(stats->rssi || stats->adv_rssi)
		|| !(stats->age_last_rx || stats->ts_last_rx))
		return;

	sta = csm_station_find_or_add(csm->station_db, ((tlv_t *)stats->mac)->value);
	if (!sta)
		return;

	if (IS_ASSOCIATED_WITH(sta, bss->h.mac))
		goto __end;

	if (stats->age_last_rx) {
		timestamp_t now = csm_get_timestamp();
		age = extract_host64(((tlv_t *)stats->age_last_rx)->value[0]);
		ts = now - age;
	} else {
		ts = extract_host64(((tlv_t *)stats->ts_last_rx)->value[0]);
		age = csm_get_age(ts);
	}

	sta->band_mask |= BIT(bss->band);
	sta->last_band = bss->band;
	sta->last_channel = bss->channel;
	CSM_LOCK(sta);
	seenbssid =
		csm_seen_bssid_find_or_add(sta, bss->mdid, bss->h.mac);
	if (seenbssid) {
		if (csm_get_age(seenbssid->last_ts) > (uint32_t)age) {
			seenbssid->last_ts = ts;
			if (stats->adv_rssi) {
				seenbssid->last_rssi = (int8_t)(*(CSM_RPE_IE_GET_VALUE(stats->adv_rssi) + 0));
				seenbssid->ch = *(CSM_RPE_IE_GET_VALUE(stats->adv_rssi) + 2);
			} else {
				seenbssid->last_rssi = extract_host32(((tlv_t *)stats->rssi)->value[0]);
				seenbssid->ch = bss->channel;
			}
			STA_UPDATE_RSSI_TS(sta, seenbssid->last_ts);
/*			CSM_DEBUG("update rssi(%d) of nonassoc sta [%" MACFMT "]: age %llu",
				seenbssid->last_rssi, MACARG(sta->h.mac), age);*/
		}
	}
	CSM_UNLOCK(sta);

__end:
	csm_put(sta);
}

static int
csm_process_event_nonassoc_sta_phy_stats(csmctx_t * csm, csmmsgh_t * h,
					 bss_table_t * bss, drvctx_t * drv)
{
	csm_parse_and_process_sta_tlv(csm, h, bss,
		csm_update_nonassoc_sta_stats);

	if (bss)
		csm_bss_put(bss);
	return 0;
}

static void csm_update_peer_latest_assoc(csmctx_t *csm,
	uint8_t *assoc, uint16_t len)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)assoc;
	sta_table_t *sta = csm_station_find(csm->station_db, wh->addr2);
	if (!sta)
		return;

	if (sta->assoc_info.latest_assoc)
		CSM_FREE(sta->assoc_info.latest_assoc);
	sta->assoc_info.latest_assoc = CSM_MALLOC(len);
	if (sta->assoc_info.latest_assoc) {
		COPYMEM(sta->assoc_info.latest_assoc, assoc, len);
		sta->assoc_info.latest_assoc_len = len;
		CSM_DUMP("latest assoc resp", sta->assoc_info.latest_assoc, sta->assoc_info.latest_assoc_len);
	}
	csm_station_put(sta);
}

static int csm_process_event_assoc(csmctx_t *csm,
	csmmsgh_t *h, bss_table_t *bss, drvctx_t *drv)
{
	evt_assoc_t *ea = (evt_assoc_t *)h;
	uint16_t len = le_to_host16(ea->cookie_len);

	if (!bss)
		return 0;

	if (len > sizeof(struct ieee80211_frame))
		csm_update_peer_latest_assoc(csm, ea->cookie + 1, len - 1);

	csm_bss_put(bss);
	return 0;
}

static inline uint32_t csm_get_frame_assoc_fixed_len(int is_reassoc)
{
	int need_len = 2 + 2;
	if (is_reassoc)
		need_len += 6;
	return need_len;
}

static void csm_process_mbo_oce_attr(void *ctx, uint8_t *frm)
{
	sta_table_t *sta = GET_STA_FROM_FRAME_CTX(ctx);

	switch (*frm) {
	case WIFI_MBO_ATTR_NONPREF_CHAN:
		csm_parse_mbo_nonpref_chan(sta, frm + 2, frm[1]);
		break;
	case WIFI_MBO_ATTR_CELL_CAP:
		csm_parse_mbo_cell_cap(sta, frm + 2, frm[1]);
		break;
	default:
		break;
	}
}

static void csm_process_mbo_oce_ie(void *ctx,
	uint8_t *frame, uint8_t len)
{
	int ret = csm_check_frame_ie_len(0, frame, len);
	if (ret < 0) {
		CSM_WARNING("MBO IE parsed failed: len mismatch");
		return;
	}
	csm_process_frame(0, frame, len,
		ctx, NULL, csm_process_mbo_oce_attr);
}

static void csm_process_assoc_req_ie(void *ctx,
	uint8_t *frm)
{
	sta_table_t *sta = GET_STA_FROM_FRAME_CTX(ctx);
	bss_table_t *bss = GET_BSS_FROM_FRAME_CTX(ctx);

	switch (*frm) {
	case IEEE80211_ELEMID_SUPPCHAN:
		csm_parse_supp_chan(sta, frm + 2, frm[1]);
		break;
	case IEEE80211_ELEMID_REG_CLASSES:
		sta->assoc_info.supp_opclass_ie = csm_store_ie(frm);
		csm_parse_supp_opcalss(bss, sta, frm + 2, frm[1]);
		break;
	case IEEE80211_ELEMID_RM_ENABLED:
		sta->assoc_info.rm_enabled_ie = csm_store_ie(frm);
		break;
	case IEEE80211_ELEMID_VENDOR:
		if (is_wifi_mbo_oce_ie(frm)) {
			sta->flag |= STATION_FLAG_MBO;
			csm_process_mbo_oce_ie(ctx, frm + 6, frm[1] - 4);
		}
		break;
	}
}

void csm_reset_assoc_info(sta_table_t *sta)
{
	/* no Support Opclass IE included, just consider it support all opclass */
	memset(sta->assoc_info.suppopclass_masks, 0xff, OPCLASS_MASK_BYTES);
	csm_free_nonpref_chans(sta);

	CSM_FREE_AND_INIT(sta->assoc_info.supp_opclass_ie);
	CSM_FREE_AND_INIT(sta->assoc_info.rm_enabled_ie);
}

static void csm_process_frame_assoc_req(void *ctx,
	int is_reassoc, struct ieee80211_frame *wh, uint32_t len)
{
	int ret;
	int fixed_len = csm_get_frame_assoc_fixed_len(is_reassoc);
	int ie_offset = fixed_len + sizeof(*wh);
	sta_table_t *sta = GET_STA_FROM_FRAME_CTX(ctx);

	ret = csm_check_frame_ie_len(ie_offset, (uint8_t *)wh, len);
	if (ret < 0) {
		CSM_WARNING("Process assoc req failed for %" MACFMT "-->%" MACFMT,
			is_reassoc ? "re" : "", MACARG(wh->addr2), MACARG(wh->addr1));
		return;
	}

	csm_update_peer_latest_assoc(GET_CSM_FROM_FRAME_CTX(ctx), (uint8_t *)wh, len);
	csm_reset_assoc_info(sta);

	csm_process_frame(0, ((uint8_t *)wh) + ie_offset, len - ie_offset,
		ctx, NULL, csm_process_assoc_req_ie);
}

static void csm_process_nonpref_chan_ie(void *ctx,
	uint8_t *frame, uint8_t len)
{
	struct frame_ctx *fctx = (struct frame_ctx *)ctx;
	sta_table_t *sta = GET_STA_FROM_FRAME_CTX(ctx);

	if (!fctx->u.nonpref_channel_ies)
		csm_free_nonpref_chans(sta);
	fctx->u.nonpref_channel_ies++;

	csm_parse_mbo_nonpref_chan(sta, frame, len);
}

static int csm_process_wnm_notify_req_fixed(void *ctx,
	uint8_t *frm, uint8_t *efrm)
{
	int fixed_len = 1 + 1;
	uint8_t type;

	if (frm + fixed_len > efrm)
		return -1;

	type = *(frm + 1);
	if (type != IEEE80211_ELEMID_VENDOR)
		return -2;
	return fixed_len;
}

static void csm_process_wnm_notify_req_ie(void *ctx,
	uint8_t *frm)
{
	switch (*frm) {
	case IEEE80211_ELEMID_VENDOR:
		if (is_wifi_mbo_nonpref_chan_ie(frm))
			csm_process_nonpref_chan_ie(ctx, frm + 6, frm[1] - 4);
		break;
	default:
		break;
	}
}

static void csm_process_wnm_notify_req(void *ctx,
	uint8_t *frm, uint32_t len)
{
	uint32_t fixed_len = 1 + 1;
	struct frame_ctx *fctx = (struct frame_ctx *)ctx;
	int ret = csm_check_frame_ie_len(fixed_len, frm, len);
	if (ret < 0) {
		CSM_WARNING("Process wnm notify req failed: len is not correct");
		return;
	}

	fctx->u.nonpref_channel_ies = 0;
	csm_process_frame(0, frm, len, ctx,
		csm_process_wnm_notify_req_fixed,
		csm_process_wnm_notify_req_ie);
}

static void csm_process_frame_action(void *ctx,
	struct ieee80211_frame *wh, uint32_t len)
{
	struct ieee80211_action *action = (struct ieee80211_action *)(wh + 1);
	uint32_t min_len = sizeof(*wh) + sizeof(*action);
	if (len < min_len) {
		CSM_WARNING(PPREFIX "Drop the action frame: frame length(%u) is not enough",
			len);
		return;
	}

	switch (action->category) {
	case IEEE80211_ACTION_CAT_WNM:
		switch (action->action) {
		case IEEE80211_WNM_NOTIFICATION_REQ:
			csm_process_wnm_notify_req(ctx,
				(uint8_t *)(action + 1),len - min_len);
			break;
		default:
			break;
		}
	default:
		break;
	}
}

void csm_parse_rpe_frame_block(void **ies,
	uint8_t *frm, uint16_t type, uint16_t len)
{
	static RPE_FRAME_PARSE_T frm_parse;

	*ies = (void *)&frm_parse;
	memset(&frm_parse, 0, sizeof(frm_parse));

	switch (type) {
	case TLVTYPE_CHANNEL_BAND:
		frm_parse.frm_info = frm;
		break;
	case TLVTYPE_FRAME:
		frm_parse.frm = frm;
		break;
	default:
		break;
	}
}

static void csm_process_rpe_frame_block(void *ctx,
	void *ies, uint8_t *eblock, int more)
{
	RPE_FRAME_PARSE_T *parse = (RPE_FRAME_PARSE_T *)ies;
	uint32_t len = 0;
	struct ieee80211_frame *wh;
	struct frame_ctx *fctx = (struct frame_ctx *)ctx;
	bss_table_t *bss = fctx->bss;
	csmctx_t *csm = fctx->csm;
	sta_table_t *sta = NULL;

	if (!parse->frm) {
		CSM_WARNING("Discard the rpe message for %" MACFMT ": not include frame in it",
			MACARG(bss->h.mac));
		return;
	}

	len = CSM_RPE_IE_GET_LEN(parse->frm);
	if (len < sizeof(*wh)) {
		CSM_WARNING("Discard the rpe message for %" MACFMT ": frame len(%s) is not correct",
			MACARG(bss->h.mac), len);
		return;
	}
	wh = (struct ieee80211_frame *)CSM_RPE_IE_GET_VALUE(parse->frm);
	if ((wh->fc[0] & IEEE80211_FC0_TYPE_MASK)
		!= IEEE80211_FC0_TYPE_MGT) {
		CSM_WARNING("Discard the rpe message for %" MACFMT ": frame type(%02x) is not management",
			MACARG(bss->h.mac), wh->fc[0]);
		return;
	}

	sta = csm_station_find_or_add(csm->station_db, wh->addr2);
	if (!sta)
		return;
	fctx->sta = sta;

	switch (wh->fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
		csm_process_frame_assoc_req(ctx, 0, wh, len);
		break;
	case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
		csm_process_frame_assoc_req(ctx, 1, wh, len);
		break;
	case IEEE80211_FC0_SUBTYPE_ACTION:
		csm_process_frame_action(ctx, wh, len);
		break;
	default:
		break;
	}

	csm_station_put(sta);
}

static int
csm_process_event_frame(csmctx_t * csm, csmmsgh_t * h,
	bss_table_t * bss, drvctx_t * drv)
{
	struct frame_ctx ctx;
	uint16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;

	if (bss)
		CSM_DEBUG("Parse the rpe message from %s: bssid is %" MACFMT,
			drv ? "local" : "slave", MACARG(bss->h.mac));
	else
		CSM_DEBUG("Parse the rpe message from %s: bssid is unknow",
			drv ? "local" : "slave");

	ctx.csm = csm;
	ctx.bss = bss;
	ctx.sta = NULL;

	csm_parse_rpe_tlv((void *)&ctx, payload, payload_len,
		NULL, NULL, csm_parse_rpe_frame_block,
		csm_process_rpe_frame_block);

	if (bss)
		csm_bss_put(bss);
	return 0;
}

typedef struct {
	uint8_t *name;
	uint8_t *radio_id;
	uint8_t *state;
	uint8_t *maxbss;
	uint8_t *nonop_chans;
	uint8_t *min_freq_seps;
	uint8_t *opclass;
	uint8_t *prefs;
} RPE_RADIO_PARSE_T;
RPE_RADIO_PARSE_T g_radio_parse;
radio_table_t *g_radio = NULL;

static void csm_init_rpe_radio_block(void)
{
	memset(&g_radio_parse, 0, sizeof(g_radio_parse));
	if (g_radio) {
		csm_radio_put(g_radio);
		g_radio = NULL;
	}
}

static int csm_check_rpe_radio_block(uint16_t type)
{
	if (TLVTYPE_OPCLASS_INFO == type
		|| TLVTYPE_OPCLASS == type)
		return 1;
	return 0;
}

static void csm_parse_rpe_radio_block(void **ies,
	uint8_t *frm, uint16_t type, uint16_t len)
{
	*ies = (void *)&g_radio_parse;

	if (csm_check_rpe_radio_block(type))
		memset(&g_radio_parse, 0, sizeof(g_radio_parse));

	switch (type) {
	case TLVTYPE_RADIO_NAME:
		g_radio_parse.name = frm;
		break;
	case TLVTYPE_RADIO_STATE:
		g_radio_parse.state = frm;
		break;
	case TLVTYPE_RADIO_MAC:
		g_radio_parse.radio_id = frm;
		break;
	case TLVTYPE_MAX_BSSES:
		g_radio_parse.maxbss = frm;
		break;
	case TLVTYPE_NONOP_CHANS:
		g_radio_parse.nonop_chans = frm;
		break;
	case TLVTYPE_MIN_FREQ_SEPS:
		g_radio_parse.min_freq_seps = frm;
		break;
	case TLVTYPE_OPCLASS_INFO:
	case TLVTYPE_OPCLASS:
		g_radio_parse.opclass = frm;
		break;
	case TLVTYPE_PREFERENCES:
		g_radio_parse.prefs = frm;
		break;
	default:
		break;
	}
}

static inline void csm_reset_radio_opclass_info(radio_table_t *radio)
{
	radio->opclass_nums = 0;
	memset(radio->opclasses, 0, sizeof(radio->opclasses));
}

static int csm_check_radio_opclass_info_parse(RPE_RADIO_PARSE_T *parse)
{
	if (!parse->opclass
		|| !parse->nonop_chans
		|| !parse->min_freq_seps)
		return 0;

	if (CSM_RPE_IE_GET_LEN(parse->opclass) < 2)
		return 0;
	return 1;
}

static void csm_update_opclass_nonop_chans(radio_table_t *radio,
	opclass_entry_t *opclass_info, uint8_t *chans, uint16_t len)
{
	int i;
	/* chans format is uint8_t[], which include all the non operable channels */
	for (i = 0; i < len; i++) {
		chan_entry_t *entry = csm_find_and_add_opclass_chan_entry(opclass_info, chans[i]);
		if (entry) {
			entry->static_nonoperable = 1;
			entry->reason = CSM_CHAN_REASON_UNAVAILABLE;
			entry->preference = 0;
			CSM_DEBUG("Update channel %u to Static NON-OPERABLE for radio %" MACFMT,
				entry->chan, MACARG(radio->h.mac));
		}
	}
}

static void csm_update_opclass_min_freq_seps(radio_table_t *radio,
	opclass_entry_t *opclass_info, uint8_t *pairs, uint16_t len)
{
	int i;
	/* pairs format is (uint8_t, uint8_t)[] */
	for (i = 0; i < len / 2; i++) {
		chan_entry_t *entry = csm_find_and_add_opclass_chan_entry(opclass_info, pairs[i * 2]);
		if (entry) {
			entry->min_freq_separation = pairs[i * 2 + 1];
			CSM_DEBUG("Update min freq sep for channel %u to %u for radio %" MACFMT,
				entry->chan, entry->min_freq_separation, MACARG(radio->h.mac));
		}
	}
}

static void csm_update_opclass_prefs(radio_table_t *radio,
	opclass_entry_t *opclass_info, uint8_t *pairs, uint16_t len)
{
	int i;
	/* pairs format is (uint8_t, uint8_t)[] */
	for (i = 0; i < len / 2; i++) {
		chan_entry_t *entry = csm_find_and_add_opclass_chan_entry(opclass_info, pairs[i * 2]);
		uint8_t val = pairs[i * 2 + 1];
		if (entry) {
			entry->preference = (val >> 4) & 0x0F;
			entry->reason = val & 0x0F;
			CSM_DEBUG("Update preference for channel %u to %u for radio %" MACFMT,
				entry->chan, entry->preference, MACARG(radio->h.mac));
		}
	}
}

static void csm_update_opclass_info_from_radio_info(radio_table_t *radio,
	RPE_RADIO_PARSE_T *parse)
{
	opclass_entry_t *entry = NULL;
	uint8_t opclass = *(CSM_RPE_IE_GET_VALUE(parse->opclass));
	if (NULL == (entry = csm_find_and_add_radio_opclass_entry(radio, opclass))) {
		CSM_WARNING("Can not add more opclass entry for radio %" MACFMT,
			MACARG(radio->h.mac));
		return;
	}

	entry->bandwidth = *(CSM_RPE_IE_GET_VALUE(parse->opclass) + 1);
	entry->max_txpower = *(CSM_RPE_IE_GET_VALUE(parse->opclass) + 2);
	csm_update_opclass_nonop_chans(radio, entry, CSM_RPE_IE_GET_VALUE(parse->nonop_chans),
		CSM_RPE_IE_GET_LEN(parse->nonop_chans));
	csm_update_opclass_min_freq_seps(radio, entry, CSM_RPE_IE_GET_VALUE(parse->min_freq_seps),
		CSM_RPE_IE_GET_LEN(parse->min_freq_seps));
}

static void csm_process_rpe_radio_info_block(void *ctx,
	void *ies, uint8_t *eblock, int more)
{
	csmctx_t *csm = (csmctx_t *)ctx;
	RPE_RADIO_PARSE_T *parse = (RPE_RADIO_PARSE_T *)ies;
	static int update_opclass = 0;

	if (parse->radio_id
		&& CSM_RPE_IE_GET_LEN(parse->radio_id) >= ETH_ALEN) {
		if (g_radio)
			csm_radio_put(g_radio);

		g_radio = csm_radio_find_or_add(csm->radio_db,
			CSM_RPE_IE_GET_VALUE(parse->radio_id));
		update_opclass = 1;
	}

	if (!g_radio)
		goto __end;

	if (parse->maxbss
		&& CSM_RPE_IE_GET_LEN(parse->maxbss) >= 2)
		g_radio->maxVAPs = *(CSM_RPE_IE_GET_VALUE(parse->maxbss));

	if (parse->name
		&& strlen((char *)(CSM_RPE_IE_GET_VALUE(parse->name))) <= IFNAMSIZ
		&& CSM_RPE_IE_GET_LEN(parse->name)
			> strlen((char *)(CSM_RPE_IE_GET_VALUE(parse->name))))
			strcpy(g_radio->ifname, (char *)(CSM_RPE_IE_GET_VALUE(parse->name)));

	if (!csm_check_radio_opclass_info_parse(parse))
		goto __end;

	/* At least one valid opclass infos(TLV 545 + 546 + 547),
	 * reset the existed for updating the new opclass infos */
	if (update_opclass) {
		update_opclass = 0;
		csm_reset_radio_opclass_info(g_radio);
		CSM_DEBUG("Start try to update info for radio %" MACFMT,
			MACARG(g_radio->h.mac));
	}

	csm_update_opclass_info_from_radio_info(g_radio, parse);

__end:
	/* no more block need to process, reset and free the resouces */
	if (!more)
		csm_init_rpe_radio_block();
}

static int
csm_process_event_radio_info(csmctx_t *csm, csmmsgh_t *h,
	bss_table_t *bss, drvctx_t *drv)
{
	uint16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;

	csm_parse_rpe_tlv((void *)csm, payload, payload_len,
		csm_init_rpe_radio_block, csm_check_rpe_radio_block,
		csm_parse_rpe_radio_block, csm_process_rpe_radio_info_block);

	if (bss)
		csm_bss_put(bss);
	return 0;
}

static int csm_check_radio_opclass_status_parse(RPE_RADIO_PARSE_T *parse)
{
	if (!parse->opclass
		|| !parse->prefs)
		return 0;

	if (CSM_RPE_IE_GET_LEN(parse->opclass) < 1)
		return 0;
	return 1;
}

static void csm_update_opclass_info_from_radio_status(radio_table_t *radio,
	RPE_RADIO_PARSE_T *parse)
{
	opclass_entry_t *entry = NULL;
	uint8_t opclass = *(CSM_RPE_IE_GET_VALUE(parse->opclass));

	if (NULL == (entry = csm_find_radio_opclass_entry(radio, opclass))) {
		CSM_WARNING("Can not find opclass entry(%u) for radio %" MACFMT,
			opclass, MACARG(radio->h.mac));
		return;
	}

	csm_update_opclass_prefs(radio, entry, CSM_RPE_IE_GET_VALUE(parse->prefs),
		CSM_RPE_IE_GET_LEN(parse->prefs));
}

static void csm_process_rpe_radio_status_block(void *ctx,
	void *ies, uint8_t *eblock, int more)
{
	csmctx_t *csm = (csmctx_t *)ctx;
	RPE_RADIO_PARSE_T *parse = (RPE_RADIO_PARSE_T *)ies;

	if (parse->radio_id
		&& CSM_RPE_IE_GET_LEN(parse->radio_id) >= ETH_ALEN) {
		if (g_radio)
			csm_radio_put(g_radio);

		g_radio = csm_radio_find(csm->radio_db,
			CSM_RPE_IE_GET_VALUE(parse->radio_id));
	}

	if (!g_radio)
		return;
	if (parse->state
		&& CSM_RPE_IE_GET_LEN(parse->state) >= 1)
		g_radio->powerState = *CSM_RPE_IE_GET_VALUE(parse->state);

	if (csm_check_radio_opclass_status_parse(parse))
		csm_update_opclass_info_from_radio_status(g_radio, parse);

	/* no more block need to process, reset and free the resouces */
	if (!more)
		csm_init_rpe_radio_block();
}

static int
csm_process_event_radio_status(csmctx_t *csm, csmmsgh_t *h,
	bss_table_t *bss, drvctx_t *drv)
{
	uint16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;

	csm_parse_rpe_tlv((void *)csm, payload, payload_len,
		csm_init_rpe_radio_block, csm_check_rpe_radio_block,
		csm_parse_rpe_radio_block, csm_process_rpe_radio_status_block);

	if (bss)
		csm_bss_put(bss);
	return 0;
}


typedef struct {
	uint8_t *sta_mac;
	uint8_t *psk_keyid;
} ADDITIONAL_INFO_PARSE_T;
ADDITIONAL_INFO_PARSE_T g_additional_info_parse;

static void csm_init_additional_info_block(void)
{
	memset(&g_additional_info_parse, 0, sizeof(g_additional_info_parse));
}

static void csm_parse_additional_info_block(void **ies,
	uint8_t *frm, uint16_t type, uint16_t len)
{
	*ies = (void *)&g_additional_info_parse;

	switch (type) {
	case TLVTYPE_STA_MAC:
		g_additional_info_parse.sta_mac = frm;
		break;
	case TLVTYPE_PSK_KEYID:
		g_additional_info_parse.psk_keyid = frm;
		break;
	default:
		break;
	}
	return;
}

static void csm_process_additional_info_block(void *ctx,
	void *ies, uint8_t *eblock, int more)
{
	ADDITIONAL_INFO_PARSE_T *parse = (ADDITIONAL_INFO_PARSE_T *)ies;
	csmctx_t *csm = (csmctx_t *)ctx;
	sta_table_t *sta = NULL;
	uint8_t key_len = 0;

	if (parse->psk_keyid && parse->sta_mac) {
		sta = csm_station_find(csm->station_db, CSM_RPE_IE_GET_VALUE(parse->sta_mac));
		if (sta) {
			key_len = CSM_RPE_IE_GET_LEN(parse->psk_keyid);
			if (key_len > PSK_KEYID_MAXLEN)
				key_len = PSK_KEYID_MAXLEN;
			memcpy(sta->assoc_info.psk_keyid, CSM_RPE_IE_GET_VALUE(parse->psk_keyid), key_len);
		}
	}
	return;
}

static int
csm_process_assoc_additional_info(csmctx_t *csm, csmmsgh_t *h,
	bss_table_t *bss, drvctx_t *drv)
{
	uint16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload = h->payload;

	csm_parse_rpe_tlv((void *)csm, payload, payload_len,
		csm_init_additional_info_block, NULL,
		csm_parse_additional_info_block, csm_process_additional_info_block);

	if (bss)
		csm_bss_put(bss);
	return 0;
}

int csm_rx_rpe_msg(void *ctx, uint8_t *bssid, uint8_t *msg, uint32_t len)
{
	csmctx_t *csm;
	csmmsgh_t *h = (csmmsgh_t *)msg;
	bss_table_t *bss;

	if (!ctx || !bssid || !msg || !len)
		return -1;

	if (NULL == (csm = GET_CSMCTX(ctx)))
		return -1;

	bss = csm_bss_find(csm->bss_db, bssid);
	if (!bss)
		return -1;

	return csm_process_event_frame(csm, h, bss, NULL);
}

static int
csm_skip_event(csmctx_t * csm, csmmsgh_t * h,
			      bss_table_t * bss, drvctx_t * drv)
{
	if (bss)
		csm_bss_put(bss);
	return 0;
}

static int
csm_process_cmd_common_t(csmctx_t * csm, csmmsgh_t * h, bss_table_t * bss,
		       drvctx_t * drv)
{
	if (bss)
		csm_bss_put(bss);
	return 0;
}

static int
csm_process_cmd_sta_mac_filter(csmctx_t * csm, csmmsgh_t * h,
			       bss_table_t * bss, drvctx_t * drv)
{
	cmd_mac_filter_t *cfilter = (cmd_mac_filter_t *) h;
	sta_table_t *sta;
	if (cfilter == NULL)
		goto bail;
	if (h->api_ver >= CSM_RPE_VER(5))
		goto bail;

	sta = csm_station_find(csm->station_db, cfilter->sta_mac);
	if (sta) {
		CSM_LOCK(sta);
		if (le_to_host16(cfilter->allow_mac) == MAC_FILTER_ALLOW_MAC) {
			STA_WHITELIST(sta);
		} else {
			STA_BLACKLIST(sta);
		}
		CSM_UNLOCK(sta);
		csm_station_put(sta);
	} else {
		CSM_WARNING("Can not find Client[%" MACFMT
			    "] to blacklist.", MACARG(cfilter->sta_mac));
	}
      bail:

	if (bss)
		csm_bss_put(bss);
	return 0;
}
