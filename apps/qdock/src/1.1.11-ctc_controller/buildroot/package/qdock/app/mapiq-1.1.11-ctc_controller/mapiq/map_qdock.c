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

#include "map_qtn.h"
#include "map_qdock.h"
#include "map_dbg.h"
#include "map_api.h"

void map_add_entry(struct list_head *phead, stah_t *stah)
{
	map_entry_t *entry;

	if (!phead || !stah)
		return;

	entry = MAP_CALLOC(1, sizeof(*entry));
	if (NULL == entry) {
		MAP_ERROR("Can not alloc entry: %s\n", strerror(errno));
		return;
	}

	map_stadb_stah_ref(stah);
	entry->stah = stah;

	list_add_tail(&entry->lh, phead);
}

void map_free_entry(map_entry_t *entry)
{
	if (!entry)
		return;

	map_stadb_stah_unref(entry->stah);

	list_del(&entry->lh);
	MAP_FREE(entry);
}

static stah_t *map_find_stah(struct sta_sdb *db, uint8_t *mac)
{
	stah_t *stah;
	uint32_t hash = db->hash(mac);
	struct list_head *head;

	if(hash >= db->hash_size) {
		return NULL;
	}

	head = &db->stalh[hash];
	if (!head) {
		return NULL;
	}

	list_for_each_entry(stah, head, lh) {
		if (MAP_MAC_EQ(stah->mac, mac))
			return stah;
	}

	return NULL;
}

sta_table_t *map_get_stadb_sta(uint8_t *mac)
{
	stah_t *stah = NULL;

	if (!mac)
		return NULL;

	struct sta_sdb *sdb = map_get_sta_table(g_ctx.ctx);
	if (NULL == sdb) {
		MAP_ERROR("Find sta " MAP_MACFMT " failed: can not get table\n",
			MAP_MACARG(mac));
		return NULL;
	}

	stah = map_find_stah(sdb, mac);
	if (NULL != stah)
		map_stadb_stah_ref(stah);

	map_put_sta_table(sdb);

	return (sta_table_t *)stah;
}

bss_table_t *map_get_stadb_bss(uint8_t *mac)
{
	stah_t *stah = NULL;

	if (!mac)
		return NULL;

	struct sta_sdb *sdb = map_get_bss_table(g_ctx.ctx);
	if (NULL == sdb) {
		MAP_ERROR("Find bss " MAP_MACFMT " failed: can not get table\n",
			MAP_MACARG(mac));
		return NULL;
	}

	stah = map_find_stah(sdb, mac);
	if (NULL != stah)
		map_stadb_stah_ref(stah);

	map_put_bss_table(sdb);

	return (bss_table_t *)stah;
}

radio_table_t *map_get_stadb_radio(uint8_t *mac)
{
	stah_t *stah = NULL;

	if (!mac)
		return NULL;

	struct sta_sdb *sdb = map_get_radio_table(g_ctx.ctx);
	if (NULL == sdb) {
		MAP_ERROR("Find radio " MAP_MACFMT " failed: can not get table\n",
			MAP_MACARG(mac));
		return NULL;
	}

	stah = map_find_stah(sdb, mac);

	map_put_radio_table(sdb);

	return (radio_table_t *)stah;
}

bss_table_t *map_get_radio_first_bss(radio_table_t *radio)
{
	bss_table_t *bss = NULL;
	struct list_head *head;

	CSM_LOCK(radio);
	head = &radio->bss_head;
	bss = list_entry(head->next, typeof(*bss), radio_lh);
	if (bss)
		map_stadb_stah_ref(bss);
	CSM_UNLOCK(radio);

	return bss;
}

bss_table_t *map_get_radio_first_vap_in_repeater(radio_table_t *radio)
{
	bss_table_t *bss = NULL;
	struct list_head *head;

	CSM_LOCK(radio);
	head = &radio->bss_head;

	list_for_each_entry(bss, head, radio_lh) {
		if (bss && bss->iftype == NODE_TYPE_VAP) {
			map_stadb_stah_ref(bss);
			break;
		}
	}
	CSM_UNLOCK(radio);

	return bss;
}

opclass_entry_t *map_get_radio_opclass_entry(radio_table_t *radio)
{
	opclass_entry_t *opclass_entry = NULL, *opclass_entry_tmp = NULL,
			*array = radio->opclasses;
        int array_cnt = radio->opclass_nums;
        uint8_t i;

        for (i = 0; i < array_cnt; i++) {
                opclass_entry_tmp = array + i;
                if (opclass_entry_tmp->global_opclass == radio->opclass) {
			opclass_entry = opclass_entry_tmp;
			break;
		}
        }

        return opclass_entry;
}

uint8_t map_get_radio_phytype(radio_table_t *radio)
{
	bss_table_t *bss;
	uint8_t phytype;

	bss = map_get_radio_first_bss(radio);
	if (bss) {
		phytype = bss->phy_type;
		map_stadb_stah_unref(bss);
		return phytype;
	}

	MAP_ERROR("cannot find the bss to getting phytype\n");
	return 0;
}

uint8_t map_get_radio_feature(radio_table_t *radio)
{
        bss_table_t *bss;
	uint8_t feature = 0;

	bss = map_get_radio_first_bss(radio);
        if (!bss) {
		MAP_ERROR("cannot find the bss to getting drv_cap\n");
		return 0;
	}

	if (bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_MONITOR)
		feature |= MAP_FEATURE_REPORT_ONCHAN_UNASSOC;
	if (bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_OMONITOR)
		feature |= MAP_FEATURE_REPORT_OFFCHAN_UNASSOC;
	map_stadb_stah_unref(bss);

        return feature;
}

typedef struct {
	const uint8_t *mac;
} map_radio_param_t;

typedef struct {
	const uint8_t *radio_mac;
	const uint8_t *bss_mac;
} map_bss_param_t;

typedef struct {
	const uint8_t *bssid;
	const uint8_t *mac;
} map_sta_param_t;

static void map_find_staes(struct list_head *phead,
	struct sta_sdb *(*get_db_cb)(void *),
	void (*put_db_cb)(struct sta_sdb *),
	int (*filter_cb)(stah_t *, void *), void *param)
{
	int i;
	stah_t *stah;
	struct sta_sdb *sdb;

	sdb = get_db_cb(g_ctx.ctx);
	if (NULL == sdb) {
		MAP_ERROR("Get sta table failed\n");
		return;
	}

	for (i = 0; i < sdb->hash_size; i++) {
		struct list_head *head = &sdb->stalh[i];
		list_for_each_entry(stah, head, lh) {
			if (filter_cb && filter_cb(stah, param))
				continue;

			map_add_entry(phead, stah);
		}
	}

	put_db_cb(sdb);
}

static inline int map_filter_sta_with_bssid(stah_t *stah, void *param)
{
	sta_table_t *sta = (sta_table_t *)stah;
	map_sta_param_t *sta_param = (map_sta_param_t *)param;
	if (!MAP_STA_IS_ASSOCIATED(sta))
		return 1;
	if (!param)
		return 0;
	if ((sta_param->bssid && !MAP_MAC_IS_NULL(sta_param->bssid)
		&& !MAP_MAC_EQ(sta->assoc_info.assoc_bssid, sta_param->bssid))
		|| (sta_param->mac && !MAP_MAC_IS_NULL(sta_param->mac)
		&& !MAP_MAC_EQ(sta->h.mac, sta_param->mac)))
		return 1;
	return 0;
}

static inline int map_filter_non_assoc_sta(stah_t *stah, void *param)
{
	sta_table_t *sta = (sta_table_t *)stah;

	if (MAP_STA_IS_ASSOCIATED(sta))
		return 1;
	return 0;
}

static inline int map_filter_radio_with_mac(stah_t *stah, void *param)
{
	map_radio_param_t *radio_param = (map_radio_param_t *)param;
	radio_table_t *radio = (radio_table_t *)stah;

	if (!param || MAP_MAC_IS_NULL(radio_param->mac))
		return 0;

	if (!MAP_MAC_EQ(radio->h.mac, radio_param->mac))
		return 1;
	return 0;
}

static inline int map_filter_bss_with_mac(stah_t *stah, void *param)
{
	map_bss_param_t *bss_param = (map_bss_param_t *)param;
	bss_table_t *bss = (bss_table_t *)stah;

	if (!param)
		return 0;

	if (!MAP_MAC_IS_NULL(bss_param->bss_mac)) {
		if (!bss)
			return 1;

		if (!MAP_MAC_IS_NULL(bss->h.mac)) {
			if (MAP_MAC_EQ(bss->h.mac, bss_param->bss_mac))
				return 0;
			else
				return 1;
		}
		else
			return 1;
	}

	if (!MAP_MAC_IS_NULL(bss_param->radio_mac)) {
		if (!bss->radio)
			return 1;

		if (!MAP_MAC_IS_NULL(bss->radio->h.mac)) {
			if (MAP_MAC_EQ(bss->radio->h.mac, bss_param->radio_mac))
				return 0;
			else
				return 1;
		}
		else
			return 1;
	}

	return 0;
}

void map_find_staes_with_bssid(struct list_head *phead,
	const uint8_t *mac, const uint8_t *bssid)
{
	map_sta_param_t param;
	param.mac = mac;
	param.bssid = bssid;

	map_find_staes(phead, map_get_sta_table, map_put_sta_table,
		map_filter_sta_with_bssid, (void *)&param);
}

void map_find_non_assoc_staes(struct list_head *phead)
{
	map_find_staes(phead, map_get_sta_table, map_put_sta_table,
		map_filter_non_assoc_sta, NULL);
}

void map_find_radios(struct list_head *phead, uint8_t *radio_id)
{
	map_radio_param_t param;
	param.mac = radio_id;

	map_find_staes(phead, map_get_radio_table, map_put_radio_table,
		map_filter_radio_with_mac, (void *)&param);
}

void map_find_bsses(struct list_head *phead, uint8_t *radio_id,
	uint8_t *dev_id)
{
	map_bss_param_t param;
	param.radio_mac = radio_id;
	param.bss_mac = dev_id;

	map_find_staes(phead, map_get_bss_table, map_put_bss_table,
		map_filter_bss_with_mac, (void *)&param);
}

sta_seen_bssid_t *map_find_seenbssid(sta_table_t *sta,
	uint8_t *bssid)
{
	sta_seen_bssid_t *seen_bssid = NULL;
	sta_seen_mdid_t *seen_mdid = NULL;

	CSM_LOCK(sta);
	list_for_each_entry(seen_mdid, &sta->seen_mdid_lh, lh) {
		list_for_each_entry(seen_bssid, &seen_mdid->seen_bssid_lh, lh) {
			if(MAP_MAC_EQ(seen_bssid->bssid, bssid)) {
				CSM_UNLOCK(sta);
				return seen_bssid;
			}
		}
	}
	CSM_UNLOCK(sta);

	return NULL;
}

static void map_build_rpe_head(map_rpemsg_t *head, uint16_t id, uint8_t coding,
	uint8_t ver, uint16_t len, uint8_t *bssid)
{
	MAP_DEBUG("build event [%u]: bssid " MAP_MACFMT "; ver %u; len %u\n",
		id, MAP_MACARG(bssid), ver, len);

	head->id = host_to_le16(id);
	head->coding = coding;
	head->api_ver = ver;
	head->payload_len = host_to_le16(len);
	memcpy(head->bssid, bssid, ETH_ALEN);
}

static void map_build_tlv_head(map_rpetlv_t *tlv,
	uint16_t type, uint16_t len)
{
	tlv->type = host_to_le16(type);
	tlv->len = host_to_le16(len);
	if (MAP_RPE_IE_LEN(len) > len)
		memset(tlv->value + len, 0, MAP_RPE_IE_LEN(len) - len);
}

static inline map_rpemsg_t *map_get_rpe(uint32_t space)
{
	return (map_rpemsg_t *)MAP_MALLOC(space);
}

void map_conf_bss_maptype(bss_table_t *bss, int fbss, int bbss)
{
	if (!bss)
		return;

	if (fbss)
		bss->flag |= BSS_FLAG_MAP_fBSS;
	else
		bss->flag &= (~BSS_FLAG_MAP_fBSS);
	if (bbss)
		bss->flag |= BSS_FLAG_MAP_bBSS;
	else
		bss->flag &= (~BSS_FLAG_MAP_bBSS);
}

static uint32_t map_build_reg_frame_tlv(bss_table_t *bss, uint8_t *frm,
	uint32_t space, uint8_t subtype, uint8_t *match,
	uint32_t match_len, uint32_t rx_mode)
{
	map_rpetlv_t *tlv = (map_rpetlv_t *)frm;
	uint16_t len = 0;
	uint16_t tag = TLVTYPE_FRAME_RX_SEL;

	if (rx_mode >= __MAP_FRAME_RX_LAST) {
		tag = TLVTYPE_FRAME_TX_SEL;
		rx_mode = 0;
	}

	len = 1 + 1 + 1;        /* subtype + handle + match len */
	if (!match)
		match_len = 0;
	len += match_len;

	if (space < sizeof(*tlv) + MAP_RPE_IE_LEN(len)) {
		MAP_WARN("bss " MAP_MACFMT " no space to add %02x register tlv\n",
			MAP_MACARG(bss->h.mac), subtype);
		return 0;
	}

	tlv->value[0] = subtype;
	tlv->value[1] = rx_mode;
	tlv->value[2] = match_len;
	if (match_len)
		memcpy(tlv->value + 3, match, match_len);

	map_build_tlv_head(tlv, tag, len);

	return MAP_RPE_IE_LEN(len) + sizeof(*tlv);
}

void map_send_frame_reg_rpe(bss_table_t *bss, uint8_t subtype,
	uint8_t *match, uint32_t match_len, uint32_t rx_mode)
{
	uint8_t *pos;
	map_rpemsg_t *rpe;

	MAP_DEBUG("register %s management(%02x) for bss " MAP_MACFMT "\n",
		rx_mode >= __MAP_FRAME_RX_LAST ? "tx" : "rx",
		subtype, MAP_MACARG(bss->h.mac));

	rpe = map_get_rpe(MAP_RPE_MAX_LEN);
	if (!rpe) {
		MAP_ERROR("can not alloc rpe message: %s\n", strerror(errno));
		return;
	}
	pos = rpe->payload;

	pos += map_build_reg_frame_tlv(bss, pos,
		MAP_RPE_MAX_LEN - (pos - (uint8_t *)rpe),
		subtype, match, match_len, rx_mode);

	map_build_rpe_head(rpe, CMD_REGISTER_FRAME, CSM_CODING_TLV,
		MAP_RPE_VER(6), pos - rpe->payload, bss->h.mac);

	map_send_rpe(bss->h.mac, (uint8_t *)rpe, pos - (uint8_t *)rpe);

	MAP_FREE(rpe);
}

void map_conf_backhaul_sta(bss_table_t *bss, int bsta)
{
	map_intf_feat_t feat;

	if (!bss)
		return;

	memset(&feat, 0, sizeof(feat));
	feat.feat_mask = CSM_INTF_FEAT_MAP_BSTA;

	if (bsta)
		feat.feat = CSM_INTF_FEAT_MAP_BSTA;

	map_set_intf_feat(bss->h.mac, &feat);
}

int map_cfg_chan(uint8_t *mac, uint8_t opclass,
	uint8_t chan, uint8_t txpower)
{
	return map_set_radio_power(mac, opclass, chan, txpower);
}

int map_roam_wdev_to_target_bss(uint8_t *dev_mac, uint8_t *target_mac,
	int chan, int opclass)
{
	return map_start_roam_wdev(dev_mac, target_mac, chan, opclass);
}

bss_table_t *map_get_local_bss_by_ssid(char *ssid)
{
	stah_t *stah = NULL;
	int i;
	bss_table_t *found = NULL;
	struct sta_sdb *sdb;

	if (!ssid)
		return NULL;

	sdb = map_get_bss_table(g_ctx.ctx);
	if (NULL == sdb) {
		MAP_ERROR("Find bss with ssid %s failed: can not get table\n",
			ssid);
		return NULL;
	}

	for(i = 0; i < sdb->hash_size; i++) {
		struct list_head *head = &sdb->stalh[i];
		list_for_each_entry(stah, head, lh) {
			bss_table_t *bss = (bss_table_t *)stah;
			if (!strcmp(bss->ssid, ssid)
				&& (!(bss->flag & BSS_FLAG_REMOTE))) {
				found = bss;
				map_stadb_stah_ref(stah);
				break;
			}
		}
	}

	map_put_bss_table(sdb);

	return found;
}

int map_get_bss_eatf(bss_table_t *bss)
{
	int avg_airtime = 0, count = 0, contending_airtime = 0, eatf = 0;
	sta_table_t *sta;
	map_entry_t *entry;
	struct list_head *head;
	LIST_HEAD(stas_head);

	map_find_staes_with_bssid(&stas_head, NULL, bss->h.mac);
	head = &stas_head;
	list_for_each_entry(entry, head, lh) {
		sta = (sta_table_t *)(entry->stah);
		if (sta && sta->assoc_info.avg_airtime > avg_airtime)
			avg_airtime = sta->assoc_info.avg_airtime;
	}

	if (avg_airtime)
		contending_airtime = (avg_airtime * 95) / (avg_airtime * 100);

	while (!list_empty(&stas_head)) {
		entry = list_first_entry(&stas_head, struct map_entry, lh);
		sta = (sta_table_t *)(entry->stah);
		if (sta->assoc_info.avg_airtime > contending_airtime)
			count++;
		map_free_entry(entry);
	}
	if ((avg_airtime * count) < bss->fat)
		eatf = bss->fat;
	else
		eatf = ((avg_airtime * count) + bss->fat) / (count + 1);

	return eatf;
}

void map_start_fat_monitoring_timer(uint16_t fat_period)
{
	if (fat_period)
		map_start_fat_monitoring(fat_period);
}

void map_start_stat_monitoring_timer(uint16_t stat_period)
{
	if (stat_period)
		map_start_stat_monitoring(stat_period);
}

uint8_t *map_parse_frame(uint8_t *pos, uint16_t payload_len, uint16_t *type_len)
{
	tlv_t *t;
	uint16_t type, len;
	int16_t min_len = 0;
	uint8_t found = 0;

	while (payload_len > sizeof(*t)) {
		t = (tlv_t *)pos;
		type = le_to_host16(t->type);
		len = le_to_host16(t->len);
		min_len = csm_tlv_vlen(type);

		if (payload_len < len + sizeof(*t))  {
			MAP_WARN("Drop Tag(%u): len(%u) is over left frame len(%u)",
				type, len, payload_len);
			return NULL;
		}

		if (min_len >= 0 && min_len > len) {
			MAP_WARN("Drop Tag(%u): len(%u) is not over min len(%u)",
				type, len, min_len);
			goto _next;
		}

		if (type == TLVTYPE_FRAME && len) {
			found = 1;
			break;
		}

_next:
		pos += (sizeof(*t) + CSM_IE_LEN(len));
		payload_len -= (sizeof(*t) + CSM_IE_LEN(len));
	}

	if (!found)
		return NULL;
	else {
		pos += sizeof(*t);
		*type_len = len;
		return pos;
	}
}

#define MAP_IEEE80211_SUBTYPE_ISSET(_mask, _subtype)	(mask & (1 << ((_subtype) >> 4)))
static uint8_t map_conver_filter_mask(uint32_t mask)
{
	uint8_t ret = 0xff;

	if (MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_PROBE_RESP))
		ret &= (~0x01);
	if (MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
		|| MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_REASSOC_RESP))
		ret &= (~0x02);
	if (MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_AUTH))
		ret &= (~0x04);
	return ret;
}

int map_add_sta_filter_rule(uint8_t *dev_id, uint8_t *sta,
	uint8_t rssi_mode, int8_t rssi, uint32_t mask, uint16_t reject_mode,
	uint8_t *reject_payload, uint16_t reject_payload_len)
{
	static csm_erw_list_t map_erw;

	map_erw.nums = 1;
	MAP_MAC_COPY(map_erw.entries[0].sta, sta);
	map_erw.entries[0].action = CSM_ERW_ACTION_ADD;
	map_erw.entries[0].rssi_mode = 0;
	if (rssi_mode)
		map_erw.entries[0].rssi_mode = (1 << rssi_mode);
	map_erw.entries[0].rssi = rssi;
	map_erw.entries[0].mask = map_conver_filter_mask(mask);
	map_erw.entries[0].reject_mode = reject_mode;
	map_erw.entries[0].reject_payload_len = reject_payload_len;
	map_erw.entries[0].reject_payload = reject_payload;

	return map_set_erw(dev_id, &map_erw);
}

int map_del_sta_filter_rule(uint8_t *dev_id, uint8_t *sta)
{
	static csm_erw_list_t map_erw;

	map_erw.nums = 1;
	MAP_MAC_COPY(map_erw.entries[0].sta, sta);
	map_erw.entries[0].action = CSM_ERW_ACTION_DEL;

	return map_set_erw(dev_id, &map_erw);
}

void map_start_chan_monitoring(uint8_t *radio_id)
{
	/* start chan monitoring with 1000ms/1% */
	map_start_monitoring(radio_id, 1000, 1);
}

int map_set_intf_mon_chan_conf(uint8_t *radio_id,
	uint8_t opclass, uint8_t chan)
{
	csm_intf_cfg_t cfg;
	radio_table_t *radio = NULL;

	radio = map_get_stadb_radio(radio_id);
	if (!radio) {
		MAP_ERROR("The radio table of "MAP_MACFMT" is not exist\n",
			MAP_MACARG(radio_id));
		return -1;
	}

	if (chan == radio->chan) {
		MAP_INFO("Ignore the reques, because the chan %d is operating chan\n", chan);
		return 0;
	}

	memset(&cfg, 0, sizeof(csm_intf_cfg_t));
	cfg.feat = CSM_INTF_FEAT_OMONITOR_ONDEMAND;
	cfg.feat_mask = CSM_INTF_FEAT_OMONITOR_ONDEMAND;

	cfg.mon_param.nac_chan = chan;

	return map_set_off_chan_monitoring(radio_id, &cfg);
}

void map_send_frame_to_rpe(uint8_t *bssid, uint8_t *frame, uint16_t frame_len)
{
	uint8_t *pos;
	map_rpetlv_t *tlv;
	map_rpemsg_t *rpe;

	if (MAP_RPE_MAX_LEN < MAP_RPE_IE_LEN(frame_len)
			+ sizeof(map_rpemsg_t) + sizeof(map_rpetlv_t )) {
		MAP_ERROR("frame length is over than %u\n", MAP_RPE_MAX_LEN);
		return;
	}

	rpe = (map_rpemsg_t *)MAP_MALLOC(MAP_RPE_MAX_LEN);
	if (!rpe) {
		MAP_ERROR("can not alloc rpe message: %s\n", strerror(errno));
		return;
	}

	tlv = (map_rpetlv_t *)rpe->payload;
	map_build_tlv_head(tlv, TLVTYPE_FRAME, frame_len);

	pos = tlv->value;
	memcpy(pos, frame, frame_len);
	pos += MAP_RPE_IE_LEN(frame_len);

	map_build_rpe_head(rpe, CMD_FRAME, CSM_CODING_TLV,
		MAP_RPE_VER(6), pos - rpe->payload, bssid);

	map_send_rpe(bssid, (uint8_t *)rpe, pos - (uint8_t *)rpe);

	MAP_FREE(rpe);
}

int map_conf_extcap(bss_table_t *bss,
	uint8_t *extcap, uint8_t *extcap_mask, uint32_t len)
{
	map_rpemsg_t *rpe;
	map_rpetlv_t *tlv;
	uint32_t msg_len = sizeof(map_rpemsg_t) + sizeof(*tlv) + MAP_RPE_IE_LEN(len * 2);

	if (!bss || !extcap || !extcap_mask || !len)
		return -1;

	MAP_INFO("config the extcap for " MAP_MACFMT "\n", MAP_MACARG(bss->h.mac));
	MAP_DUMP("extcap", extcap, len);
	MAP_DUMP("extcap_mask", extcap_mask, len);

	rpe = map_get_rpe(msg_len);
	if (!rpe) {
		MAP_ERROR("can not alloc rpe message: %s\n", strerror(errno));
		return -1;
	}
	tlv = (map_rpetlv_t *)rpe->payload;
	/* Add ExtCap */
	memcpy(tlv->value, extcap, len);
	/* Add ExtCap Mask */
	memcpy(tlv->value + len, extcap_mask, len);

	map_build_tlv_head(tlv, TLVTYPE_EXTCAP_SETS, len * 2);
	map_build_rpe_head(rpe, CMD_SET_USER_CAP, CSM_CODING_TLV,
		MAP_RPE_VER(6), sizeof(*tlv) + MAP_RPE_IE_LEN(len * 2), bss->h.mac);

	map_send_rpe(bss->h.mac, (uint8_t *)rpe, msg_len);
	MAP_FREE(rpe);

	return 0;
}

static uint32_t map_get_conf_appies_mask(uint32_t mask)
{
	uint32_t ret = 0;
	if (MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
		|| MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_REASSOC_RESP))
		ret |= RPE_APPIE_FOR_ASSOC;
	if (MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_BEACON))
		ret |= RPE_APPIE_FOR_BEACON;
	if (MAP_IEEE80211_SUBTYPE_ISSET(mask, IEEE80211_FC0_SUBTYPE_PROBE_RESP))
		ret |= RPE_APPIE_FOR_PROBE;
	return ret;
}

int map_conf_appies(bss_table_t *bss,
	uint32_t mask, uint8_t *ies, uint32_t len)
{
	map_rpemsg_t *rpe;
	map_rpetlv_t *tlv;
	uint32_t msg_len = sizeof(map_rpemsg_t) + sizeof(*tlv) + MAP_RPE_IE_LEN(len + sizeof(uint32_t));
	uint32_t ie_mask = 0;

	if (!bss || !mask)
		return -1;

	MAP_INFO("config the app ies (%08x) for " MAP_MACFMT "\n", mask, MAP_MACARG(bss->h.mac));
	MAP_DUMP("appies", ies, len);

	rpe = map_get_rpe(msg_len);
	if (!rpe) {
		MAP_ERROR("can not alloc rpe message: %s\n", strerror(errno));
		return -1;
	}
	tlv = (map_rpetlv_t *)rpe->payload;

	ie_mask = map_get_conf_appies_mask(mask);
	*(uint32_t *)tlv->value = host_to_le32(ie_mask);
	if (ies && len)
		memcpy(tlv->value + sizeof(uint32_t), ies, len);

	map_build_tlv_head(tlv, TLVTYPE_ADDIES, len + sizeof(uint32_t));

	map_build_rpe_head(rpe, CMD_SET_USER_CAP, CSM_CODING_TLV,
		MAP_RPE_VER(6), sizeof(*tlv) + MAP_RPE_IE_LEN(len + sizeof(uint32_t)), bss->h.mac);

	map_send_rpe(bss->h.mac, (uint8_t *)rpe, msg_len);
	MAP_FREE(rpe);

	return 0;
}
