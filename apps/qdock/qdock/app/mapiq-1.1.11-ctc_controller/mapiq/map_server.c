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
#include "map_api.h"
#include "map_qdock.h"
#include "map_dbg.h"
#include "map_ctrl.h"
#include "map_server.h"

#define WORKROUND_FOR_CENTER_FREQ_INDEX

static struct blob_buf b;

void map_blobmsg_add_mac(const char *name, uint8_t *mac)
{
#ifndef MAPIQ_DEVID_STRING_FORMAT
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, name, mac, ETH_ALEN);
#else
	char mac_string[MAP_DEVID_LEN];
	sprintf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	blobmsg_add_string(&b, name, mac_string);
#endif
}

void map_blobmsg_get_mac(struct blob_attr *attr, uint8_t *mac)
{
#ifndef MAPIQ_DEVID_STRING_FORMAT
	MAP_MAC_COPY(mac, blobmsg_data(attr));
#else
	ether_aton_r((char *)blobmsg_data(attr), (struct ether_addr *)mac);
#endif
}

static int map_method_response(struct ubus_context *ctx,
	struct ubus_request_data *req, const char *method,
	uint8_t reason, const char *func, uint32_t line)
{
	MAP_DEBUG("Method %s %s called by %s[L%u]\n", method,
		(MAP_RC_OK == reason) ? "successed" : "failed",  func, line);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, reason);
	return ubus_send_reply(ctx, req, b.head);
}

#define map_method_successed(_ctx, _req, _method)	\
	map_method_response(_ctx, _req, _method, MAP_RC_OK, __func__, __LINE__)
#define map_method_failed(_ctx, _req, _method, _reason)	\
	map_method_response(_ctx, _req, _method, _reason, __func__, __LINE__)

enum {
	MAP_GET_WIPHYS_WIPHY_ID = 0,

	__MAP_GET_WIPHYS_MAX
};

static const struct blobmsg_policy map_get_wiphys_policy[] = {
	[MAP_GET_WIPHYS_WIPHY_ID] = { .name = MAP_ATTR_WIPHY_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
};

enum {
	MAP_GET_WDEVS_WIPHY_ID = 0,
	MAP_GET_WDEVS_WDEV_ID,

	__MAP_GET_WDEVS_MAX
};

static const struct blobmsg_policy map_get_wdevs_policy[] = {
	[MAP_GET_WDEVS_WIPHY_ID] = { .name = MAP_ATTR_WIPHY_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_GET_WDEVS_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
};

static void map_fill_chan(chan_entry_t *chan_entry)
{
	void *chan_tbl = blobmsg_open_table(&b, NULL);

	blobmsg_add_u32(&b, MAP_CHAN_ATTR_CHAN_NAME, chan_entry->chan);
	blobmsg_add_u32(&b, MAP_CHAN_ATTR_FREQ_NAME, ieee80211_get_freq_from_chan(chan_entry->chan));
	blobmsg_add_u32(&b, MAP_CHAN_ATTR_NONOPERABLE_NAME, chan_entry->static_nonoperable);
	blobmsg_add_u32(&b, MAP_CHAN_ATTR_REASON_NAME, chan_entry->reason);
	blobmsg_add_u32(&b, MAP_CHAN_ATTR_PREF_NAME, chan_entry->preference);
	blobmsg_add_u32(&b, MAP_CHAN_ATTR_FREQ_SEP_NAME, chan_entry->min_freq_separation);

	blobmsg_close_table(&b, chan_tbl);
}

#ifdef WORKROUND_FOR_CENTER_FREQ_INDEX
struct center_freq_info {
	uint8_t index;
	uint8_t bandwith;
};
struct center_freq_info opclass_128_130[] = {
	{ 42,	80 },
	{ 58,	80 },
	{ 106,	80 },
	{ 122,	80 },
	{ 138,	80 },
	{ 155,	80 },
};

static inline void map_get_chan_info_for_center_freq(struct center_freq_info *info,
	uint8_t *nums, uint8_t *first)
{
	*nums = info->bandwith / 20;
	*first = info->index - (*nums / 2) * 4 + 2;
}

static void map_get_chan_for_opclass_120_130(uint8_t index, uint8_t *first, uint8_t *nums)
{
	int i;
	uint8_t incs = 1;
	uint8_t start = index;

	for (i = 0; i < ARRAY_SIZE(opclass_128_130); i++) {
		if (opclass_128_130[i].index == index) {
			map_get_chan_info_for_center_freq(&opclass_128_130[i], &incs, &start);
			break;
		}
	}
	if (first)
		*first = start;
	if (nums)
		*nums = incs;
}

static void map_build_fake_chan_entry(chan_entry_t *chans, uint8_t nums,
	struct center_freq_info *info, chan_entry_t *entry)
{
	uint8_t incs, first, i, j;

	memset(entry, 0, sizeof(*entry));

	entry->chan = info->index;
	entry->preference = 255;

	map_get_chan_info_for_center_freq(info, &incs, &first);

	for (i = 0; i < incs; i++) {
		for (j = 0; j < nums; j++) {
			if (chans[j].chan == info->index) {
				memcpy(entry, chans + j, sizeof(*entry));
				return;
			}
			if (chans[j].chan == first + i * 4)
				break;
		}
		if (j >= nums) {
			entry->static_nonoperable = 1;
			entry->preference = 0;
			return;
		}
		if (!entry->static_nonoperable && chans[i].static_nonoperable)
			entry->static_nonoperable = 1;
		if (entry->preference > chans[j].preference) {
			entry->preference = chans[j].preference;
			entry->reason = chans[j].reason;
			entry->min_freq_separation = chans[j].min_freq_separation;
		}
	}
}

static void map_fill_chans_for_opclass_120_130(opclass_entry_t *opclass_entry)
{
	int i;
	void *chan_array;
	chan_entry_t entry;

	chan_array = blobmsg_open_array(&b, MAP_OPCLASS_ATTR_CHANS_NAME);

	for (i = 0; i < ARRAY_SIZE(opclass_128_130); i++) {
		map_build_fake_chan_entry(opclass_entry->chans,
			opclass_entry->chan_nums, &opclass_128_130[i], &entry);
		map_fill_chan(&entry);
	}

	blobmsg_close_array(&b, chan_array);
}
#endif

static void map_fill_chans(opclass_entry_t *opclass_entry)
{
	void *chan_array;
	chan_entry_t *chan_entries;
	uint8_t i;

	chan_array = blobmsg_open_array(&b, MAP_OPCLASS_ATTR_CHANS_NAME);
	chan_entries = opclass_entry->chans;
	for (i = 0; i < opclass_entry->chan_nums; i++)
		map_fill_chan(chan_entries + i);

	blobmsg_close_array(&b, chan_array);
}

static void map_fill_opclass(opclass_entry_t *opclass_entry)
{
	void *opclass_tbl = blobmsg_open_table(&b, NULL);

	blobmsg_add_u32(&b, MAP_OPCLASS_ATTR_ID_NAME, opclass_entry->global_opclass);
	blobmsg_add_u32(&b, MAP_OPCLASS_ATTR_BW_NAME, opclass_entry->bandwidth);
	blobmsg_add_u32(&b, MAP_OPCLASS_ATTR_MAX_POWER_NAME, opclass_entry->max_txpower);

#ifdef WORKROUND_FOR_CENTER_FREQ_INDEX
	if (opclass_entry->global_opclass == 128
		|| opclass_entry->global_opclass == 130)
		map_fill_chans_for_opclass_120_130(opclass_entry);
	else
#endif
	map_fill_chans(opclass_entry);

	blobmsg_close_table(&b, opclass_tbl);
}

static void map_fill_opclasses(uint8_t opclass_nums, opclass_entry_t * opclasses)
{
	void *opclasses_array;
	uint8_t i;

	if (!opclass_nums) {
		MAP_INFO("No opclass entry in the radio table.\n");
		return;
	}
	opclasses_array = blobmsg_open_array(&b, MAP_WIPHY_ATTR_OPCLASSES_NAME);

	for (i = 0; i < opclass_nums; i++)
		map_fill_opclass(opclasses + i);

	blobmsg_close_array(&b, opclasses_array);
}

static void map_fill_limits(radio_table_t *radio)
{
	void *limits_array =
		blobmsg_open_array(&b, MAP_WIPHY_ATTR_LIMITS_NAME);
	void *limit_tbl = blobmsg_open_table(&b, NULL);

	blobmsg_add_u32(&b, MAP_LIMIT_ATTR_TYPES_NAME, (1 << MAP_IFTYPE_AP));
	blobmsg_add_u32(&b, MAP_LIMIT_ATTR_MAX_NAME, radio->maxVAPs);

	blobmsg_close_table(&b, limit_tbl);
	blobmsg_close_array(&b, limits_array);
}

static void map_fill_wiphy(radio_table_t * radio, int only_basic)
{
	opclass_entry_t *opclass_entry = NULL;

	if (!radio) {
		MAP_ERROR("radio table is not available!\n");
		return;
	}

	opclass_entry = map_get_radio_opclass_entry(radio);
	map_blobmsg_add_mac(MAP_WIPHY_ATTR_ID_NAME, radio->h.mac);
	blobmsg_add_string(&b, MAP_WIPHY_ATTR_NAME_NAME, radio->ifname);
	blobmsg_add_u32(&b, MAP_WIPHY_ATTR_PHYTYPE_NAME, map_get_radio_phytype(radio));
	blobmsg_add_u32(&b, MAP_WIPHY_ATTR_OPCLASS_NAME, radio->opclass);
	blobmsg_add_u32(&b, MAP_WIPHY_ATTR_CHAN_NAME, radio->chan);
	blobmsg_add_u32(&b, MAP_WIPHY_ATTR_FREQ_NAME,
		ieee80211_get_freq_from_chan(radio->chan));
	if (opclass_entry && opclass_entry->bandwidth)
		blobmsg_add_u32(&b, MAP_WIPHY_ATTR_BW_NAME, opclass_entry->bandwidth);
	else
		blobmsg_add_u32(&b, MAP_WIPHY_ATTR_BW_NAME, 20);
	blobmsg_add_u32(&b, MAP_WIPHY_ATTR_PS_STATE_NAME, (radio->powerState &\
		CSM_RADIO_POWER_SAVE) ? 1 : 0);
	if (opclass_entry && opclass_entry->max_txpower)
		blobmsg_add_u32(&b, MAP_WIPHY_ATTR_TXPOWER_NAME, opclass_entry->max_txpower
			- radio->tx_power_backoff);
	else
		blobmsg_add_u32(&b, MAP_WIPHY_ATTR_TXPOWER_NAME, 7);

	if (only_basic)
		return;

	blobmsg_add_u32(&b, MAP_WIPHY_ATTR_FEATURES_NAME, map_get_radio_feature(radio));

	map_fill_limits(radio);

	map_fill_opclasses(radio->opclass_nums, radio->opclasses);
}

static int map_get_wiphys(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_GET_WIPHYS_MAX];
	void *wiphy_array;
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	LIST_HEAD(radios_head);

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_get_wiphys_policy, __MAP_GET_WIPHYS_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (tb[MAP_GET_WIPHYS_WIPHY_ID]
		&& blobmsg_len(tb[MAP_GET_WIPHYS_WIPHY_ID]) >= MAP_DEVID_LEN)
		map_blobmsg_get_mac(tb[MAP_GET_WIPHYS_WIPHY_ID], wiphy_id);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, MAP_RC_OK);
	wiphy_array = blobmsg_open_array(&b, MAP_ATTR_WIPHYS_NAME);

	map_find_radios(&radios_head, wiphy_id);
	while (!list_empty(&radios_head)) {
		map_entry_t *entry = list_first_entry(&radios_head, struct map_entry, lh);
		void *wiphy_tbl = blobmsg_open_table(&b, NULL);
		map_fill_wiphy((radio_table_t *)(entry->stah), 0);
		blobmsg_close_table(&b, wiphy_tbl);

		map_free_entry(entry);
	}
	blobmsg_close_array(&b, wiphy_array);

	return ubus_send_reply(ctx, req, b.head);
}

static void map_fill_wdev(bss_table_t *bss, uint8_t *state)
{
	uint32_t value32;
	if (!bss) {
		MAP_ERROR("bss table is not available\n");
		return;
	}

	if (!bss->radio) {
		MAP_ERROR("radio table of bss "MAP_MACFMT" is not available\n",
			MAP_MACARG(bss->h.mac));
		return;
	}

	map_blobmsg_add_mac(MAP_WDEV_ATTR_ID_NAME, bss->h.mac);
	blobmsg_add_string(&b, MAP_WDEV_ATTR_NAME_NAME, bss->ifname);
	map_blobmsg_add_mac(MAP_WDEV_ATTR_WIPHY_ID_NAME, bss->radio->h.mac);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_IFTYPE_NAME, bss->iftype);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_IFTYPE_1905_NAME, bss->radio->iftype_1905);
	map_blobmsg_add_mac(MAP_WDEV_ATTR_BSSID_NAME, bss->bssid);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_SSID_NAME, bss->ssid,
		bss->ssid_len);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_BINTVL_NAME, bss->binterval);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_HT_CAPA_NAME,
		bss->ht_capability, HT_CAPABILITY_LEN);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_HT_OP_NAME,
		bss->ht_operation, HT_OPERATION_LEN);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_VHT_CAPA_NAME,
		bss->vht_capability, VHT_CAPABILITY_LEN);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_VHT_OP_NAME,
		bss->vht_operation, VHT_OPERATION_LEN);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_HE_CAPA_NAME,
		bss->he_capability, IEEE80211_HECAP_MAXLEN);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_HE_OP_NAME,
		bss->he_operation, IEEE80211_HEOP_MAXLEN);
	if (state)
		blobmsg_add_u32(&b, MAP_WDEV_ATTR_STATUS_NAME, *state);
	else
		blobmsg_add_u32(&b, MAP_WDEV_ATTR_STATUS_NAME, BSS_IS_UP(bss) ? 1 : 0);
	value32 = (bss->capabilities_infomation[1]<<8) | bss->capabilities_infomation[0];
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_CAPINFO_NAME, value32);
}

static int map_get_wdevs(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_GET_WDEVS_MAX];
	void *wdev_array;
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	LIST_HEAD(bsses_head);

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_get_wdevs_policy, __MAP_GET_WDEVS_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (tb[MAP_GET_WDEVS_WIPHY_ID]
		&& blobmsg_len(tb[MAP_GET_WDEVS_WIPHY_ID]) >= MAP_DEVID_LEN)
		map_blobmsg_get_mac(tb[MAP_GET_WDEVS_WIPHY_ID], wiphy_id);

	if (tb[MAP_GET_WDEVS_WDEV_ID]
		&& blobmsg_len(tb[MAP_GET_WDEVS_WDEV_ID]) >= MAP_DEVID_LEN)
		map_blobmsg_get_mac(tb[MAP_GET_WDEVS_WDEV_ID], wdev_id);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, MAP_RC_OK);
	wdev_array = blobmsg_open_array(&b, MAP_ATTR_WDEVS_NAME);

	map_find_bsses(&bsses_head, wiphy_id, wdev_id);
	while (!list_empty(&bsses_head)) {
		map_entry_t *entry = list_first_entry(&bsses_head, struct map_entry, lh);
		void *wdev_tbl = blobmsg_open_table(&b, NULL);
		map_fill_wdev((bss_table_t *)(entry->stah), NULL);
		blobmsg_close_table(&b, wdev_tbl);

		map_free_entry(entry);
	}

	blobmsg_close_array(&b, wdev_array);

	return ubus_send_reply(ctx, req, b.head);
}

static const struct ubus_method map_intf_methods[] = {
	UBUS_METHOD(MAP_METHOD_GET_WIPHYS_NAME, map_get_wiphys, map_get_wiphys_policy),
	UBUS_METHOD(MAP_METHOD_GET_WDEVS_NAME, map_get_wdevs, map_get_wdevs_policy),
};

static struct ubus_object_type map_intf_obj_type =
	UBUS_OBJECT_TYPE(MAP_INTF_OBJ_NAME, map_intf_methods);

static struct ubus_object map_intf_obj = {
	.name = MAP_INTF_OBJ_NAME,
	.type = &map_intf_obj_type,
	.methods = map_intf_methods,
	.n_methods = ARRAY_SIZE(map_intf_methods),

};

static const struct blobmsg_policy map_wiphy_policy[] = {
	[MAP_WIPHY_ATTR_ID] = { .name = MAP_WIPHY_ATTR_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_WIPHY_ATTR_OPCLASS] = { .name = MAP_WIPHY_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_WIPHY_ATTR_CHANNEL] = { .name = MAP_WIPHY_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_WIPHY_ATTR_TXPOWER] = { .name = MAP_WIPHY_ATTR_TXPOWER_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_WIPHY_ATTR_TEAR_DOWN] = { .name = MAP_WIPHY_ATTR_TEAR_DOWN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int map_config_wiphy(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *wiphy_tb[NUM_MAP_WIPHY_ATTRS];
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	radio_table_t *radio = NULL;
	uint8_t opclass, chan, power;

	blobmsg_parse(map_wiphy_policy, NUM_MAP_WIPHY_ATTRS,
		wiphy_tb, blob_data(msg), blob_len(msg));

	if (!wiphy_tb[MAP_WIPHY_ATTR_ID]) {
		MAP_WARN("Fail to config the wiphy: missing the wiphy id\n");
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);
	}

	map_blobmsg_get_mac(wiphy_tb[MAP_WIPHY_ATTR_ID], wiphy_id);

	radio = map_get_stadb_radio(wiphy_id);
	if (!radio) {
		MAP_WARN("Fail to get the wiphy from radio list\n");
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);
	}

	if (wiphy_tb[MAP_WIPHY_ATTR_OPCLASS] && wiphy_tb[MAP_WIPHY_ATTR_CHANNEL]
		&& wiphy_tb[MAP_WIPHY_ATTR_TXPOWER]) {
		opclass = (uint8_t)blobmsg_get_u32(wiphy_tb[MAP_WIPHY_ATTR_OPCLASS]);
		chan = (uint8_t)blobmsg_get_u32(wiphy_tb[MAP_WIPHY_ATTR_CHANNEL]);
		power = (uint8_t)blobmsg_get_u32(wiphy_tb[MAP_WIPHY_ATTR_TXPOWER]);

#ifdef WORKROUND_FOR_CENTER_FREQ_INDEX
		if (opclass == 128 || opclass == 130)
			map_get_chan_for_opclass_120_130(chan, &chan, NULL);
#endif

		if (map_cfg_chan(wiphy_id, opclass, chan, power) < 0)
			MAP_WARN("Fail to config the wiphy: internal config failed\n");
	}

	if (map_extcfg_cfg_wiphy((const char *)radio->ifname, wiphy_tb) < 0) {
		MAP_WARN("Fail to config the wiphy: external config failed\n");
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);
	}

	return map_method_successed(ctx, req, method);
}

static const struct blobmsg_policy map_ie_policy[NUM_MAP_IE_ATTRS] = {
	[MAP_IE_ATTR_FRAME_MASK] = { .name = MAP_IE_ATTR_FRAME_MASK_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_IE_ATTR_VALUE] = { .name = MAP_IE_ATTR_VALUE_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static void map_parse_and_conf_appie(bss_table_t *bss, struct blob_attr *attr)
{
	struct blob_attr *tb[NUM_MAP_IE_ATTRS];

	blobmsg_parse(map_ie_policy, NUM_MAP_IE_ATTRS,
		tb, blobmsg_data(attr), blobmsg_len(attr));

	if (!tb[MAP_IE_ATTR_FRAME_MASK] || !tb[MAP_IE_ATTR_VALUE]) {
		MAP_WARN("Fail to config appie: miss param\n");
	}

	map_conf_appies(bss, blobmsg_get_u32(tb[MAP_IE_ATTR_FRAME_MASK]),
		blobmsg_data(tb[MAP_IE_ATTR_VALUE]), blobmsg_len(tb[MAP_IE_ATTR_VALUE]));
}

static void map_parse_and_conf_appies(bss_table_t *bss, struct blob_attr *attrs)
{
	struct blob_attr *attr;
	int rem;
	blobmsg_for_each_attr(attr, attrs, rem)
		map_parse_and_conf_appie(bss, attr);
}

static const struct blobmsg_policy map_wdev_policy[NUM_MAP_WDEV_ATTRS] = {
	[MAP_WDEV_ATTR_ID] = { .name = MAP_WDEV_ATTR_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_WDEV_ATTR_WIPHY_ID] = { .name = MAP_WDEV_ATTR_WIPHY_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_WDEV_ATTR_MODE] = { .name = MAP_WDEV_ATTR_MODE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_WDEV_ATTR_BSSID] = { .name = MAP_WDEV_ATTR_BSSID_NAME, .type = MAP_BLOBMSG_TYPE_MAC},
	[MAP_WDEV_ATTR_SSID] = { .name = MAP_WDEV_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_WDEV_ATTR_AUTH] = { .name = MAP_WDEV_ATTR_AUTH_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_WDEV_ATTR_ENCRYP] = { .name = MAP_WDEV_ATTR_ENCRYP_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_WDEV_ATTR_KEY] = { .name = MAP_WDEV_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_WDEV_ATTR_OPCLASS] = { .name = MAP_WDEV_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_WDEV_ATTR_CHAN] = { .name = MAP_WDEV_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_WDEV_ATTR_DISABLE] = { .name = MAP_WDEV_ATTR_DISABLE_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_WDEV_ATTR_WPS] = { .name = MAP_WDEV_ATTR_WPS_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_WDEV_ATTR_MAP_MTYPES] = { .name = MAP_WDEV_ATTR_MAP_MTYPES_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_WDEV_ATTR_BACKHAUL] = { .name = MAP_WDEV_ATTR_BACKHAUL_NAME, .type = BLOBMSG_TYPE_TABLE},
	[MAP_WDEV_ATTR_EXTCAP] = { .name = MAP_WDEV_ATTR_EXTCAP_NAME, .type = BLOBMSG_TYPE_UNSPEC},
	[MAP_WDEV_ATTR_IES] = { .name = MAP_WDEV_ATTR_IES_NAME, .type = BLOBMSG_TYPE_ARRAY},
	[MAP_WDEV_ATTR_4ADDR] = { .name = MAP_WDEV_ATTR_4ADDR_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_WDEV_ATTR_HIDE] = { .name = MAP_WDEV_ATTR_HIDE_NAME, .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy map_wdev_backhaul_policy[NUM_MAP_BACKHAUL_ATTRS] = {
	[MAP_BACKHAUL_ATTR_SSID] = { .name = MAP_BACKHAUL_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_BACKHAUL_ATTR_AUTH] = { .name = MAP_BACKHAUL_ATTR_AUTH_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_BACKHAUL_ATTR_ENCRYP] = { .name = MAP_BACKHAUL_ATTR_ENCRYP_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAP_BACKHAUL_ATTR_KEY] = { .name = MAP_BACKHAUL_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static int map_create_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *wdev_tb[NUM_MAP_WDEV_ATTRS];
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	radio_table_t *radio = NULL;
	char ifname[IFNAMSIZ] = { 0 };

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_wdev_policy, NUM_MAP_WDEV_ATTRS,
		wdev_tb, blob_data(msg), blob_len(msg));

	if (!wdev_tb[MAP_WDEV_ATTR_WIPHY_ID])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(wdev_tb[MAP_WDEV_ATTR_WIPHY_ID], wiphy_id);

	radio = map_get_stadb_radio(wiphy_id);
	if (!radio)
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	if (wdev_tb[MAP_WDEV_ATTR_MODE] && wdev_tb[MAP_WDEV_ATTR_SSID]
		&& wdev_tb[MAP_WDEV_ATTR_MAP_MTYPES])
		if(blobmsg_get_u32(wdev_tb[MAP_WDEV_ATTR_MODE]) == MAP_IFTYPE_AP)
			map_config_bss_mtype((char *)blobmsg_data(wdev_tb[MAP_WDEV_ATTR_SSID]),
				(uint8_t)blobmsg_get_u32(wdev_tb[MAP_WDEV_ATTR_MAP_MTYPES]));

	if (map_extcfg_add_wdev((const char *)radio->ifname, wdev_tb, ifname) < 0) {
		MAP_WARN("Fail to create the wdev: external config failed\n");
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, MAP_WDEV_ATTR_NAME_NAME, ifname);

	return ubus_send_reply(ctx, req, b.head);
}

static int map_delete_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *wdev_tb[NUM_MAP_WDEV_ATTRS];
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	bss_table_t *bss = NULL;
	char if_name[IFNAMSIZ + 1] = { 0 };

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_wdev_policy, NUM_MAP_WDEV_ATTRS,
		wdev_tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!wdev_tb[MAP_WDEV_ATTR_ID]) {
		MAP_WARN("Fail to delete the wdev: missing the wdev id\n");
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);
	}

	map_blobmsg_get_mac(wdev_tb[MAP_WDEV_ATTR_ID], wdev_id);
	bss = map_get_stadb_bss(wdev_id);
	if (!bss) {
		MAP_WARN("Fail to delete the wdev: "
			MAP_MACFMT " not been found\n", MAP_MACARG(wdev_id));
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);
	}
	strncpy(if_name, bss->ifname, IFNAMSIZ);
	map_del_intf_config(bss->ssid);
	map_stadb_stah_unref((stah_t *)bss);

	if (map_extcfg_del_wdev((const char *)if_name) < 0) {
		MAP_WARN("Fail to config the wdev: external config failed\n");
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);
	}

	return map_method_successed(ctx, req, method);
}

static int map_config_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *wdev_tb[NUM_MAP_WDEV_ATTRS];
	struct blob_attr *param_tb[NUM_MAP_BACKHAUL_ATTRS];
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	bss_table_t *bss = NULL;
	uint8_t opclass, chan, power = 255;
	int is_backhaul_configured = 0;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_wdev_policy, NUM_MAP_WDEV_ATTRS,
		wdev_tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!wdev_tb[MAP_WDEV_ATTR_ID]) {
		MAP_WARN("Fail to config wdev: missing the wdev id\n");
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);
	}

	map_blobmsg_get_mac(wdev_tb[MAP_WDEV_ATTR_ID], wdev_id);
	bss = map_get_stadb_bss(wdev_id);
	if (!bss) {
		MAP_WARN("Fail to config wdev: "MAP_MACFMT " not been found\n",
			MAP_MACARG(wdev_id));
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);
	}

	if (wdev_tb[MAP_WDEV_ATTR_OPCLASS] && wdev_tb[MAP_WDEV_ATTR_CHAN]) {
		opclass = (uint8_t)blobmsg_get_u32(wdev_tb[MAP_WDEV_ATTR_OPCLASS]);
		chan = (uint8_t)blobmsg_get_u32(wdev_tb[MAP_WDEV_ATTR_CHAN]);
		if (map_cfg_chan(wdev_id, opclass, chan, power) < 0)
			MAP_WARN("Fail to config wdev internal config failed\n");
	}

	if (wdev_tb[MAP_WDEV_ATTR_EXTCAP]) {
		uint8_t *extcap = blobmsg_data(wdev_tb[MAP_WDEV_ATTR_EXTCAP]);
		uint32_t extcap_len = blobmsg_len(wdev_tb[MAP_WDEV_ATTR_EXTCAP]);
		if (extcap_len % 2) {
			MAP_WARN("Fail to config wdev extcapi: param is wrong\n");
			map_stadb_stah_unref((stah_t *)bss);
			return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);
		}
		if (map_conf_extcap(bss, extcap, extcap + extcap_len / 2, extcap_len / 2) < 0) {
			MAP_WARN("Fail to config wdev extcap\n");
			map_stadb_stah_unref((stah_t *)bss);
			return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);
		}
	}

	if (wdev_tb[MAP_WDEV_ATTR_IES])
		map_parse_and_conf_appies(bss, wdev_tb[MAP_WDEV_ATTR_IES]);

	if (wdev_tb[MAP_WDEV_ATTR_BACKHAUL]) {
		blobmsg_parse(map_wdev_backhaul_policy, NUM_MAP_BACKHAUL_ATTRS, param_tb,
			blobmsg_data(wdev_tb[MAP_WDEV_ATTR_BACKHAUL]),
			blobmsg_len(wdev_tb[MAP_WDEV_ATTR_BACKHAUL]));
		is_backhaul_configured = 1;
	}

	if (map_extcfg_cfg_wdev((const char *)bss->ifname, wdev_tb,
		is_backhaul_configured, param_tb) < 0) {
		MAP_WARN("Fail to config wdev: external config failed\n");
		map_stadb_stah_unref((stah_t *)bss);
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);
	}

	map_stadb_stah_unref((stah_t *)bss);

	return map_method_successed(ctx, req, method);
}

enum {
	MAP_START_WPS_WDEV_ID = 0,

	__MAP_START_WPS_MAX
};

static const struct blobmsg_policy map_start_wps_policy[] = {
	[MAP_START_WPS_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
};

static int map_start_wps(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_START_WPS_MAX];
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	bss_table_t *bss = NULL;

	blobmsg_parse(map_start_wps_policy, __MAP_START_WPS_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_START_WPS_WDEV_ID])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	if (blobmsg_len(tb[MAP_START_WPS_WDEV_ID]) < MAP_DEVID_LEN)
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	map_blobmsg_get_mac(tb[MAP_START_WPS_WDEV_ID], wdev_id);

	bss = map_get_stadb_bss(wdev_id);
	if (!bss) {
		MAP_WARN("Fail to start wps on wdev: "
			MAP_MACFMT " not been found\n", MAP_MACARG(wdev_id));
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);
	}

	if (map_extcfg_start_wps((const char *)bss->ifname) < 0)
		MAP_WARN("Fail to start wps on wdev: external start_wps failed\n");

	map_stadb_stah_unref((stah_t *)bss);

	return map_method_successed(ctx, req, method);
}

enum {
	MAP_GET_BSSCFG_WIPHY_ID = 0,
	MAP_GET_BSSCFG_WDEV_ID  = 1,

	__MAP_GET_BSSCFG_MAX
};

static const struct blobmsg_policy map_get_bsscfg_policy[] = {
	[MAP_GET_BSSCFG_WIPHY_ID] = { .name = MAP_ATTR_WIPHY_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_GET_BSSCFG_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
};

static void map_fill_bsscfg(bss_table_t *bss, map_bsscfg_t *bss_cfg)
{
	if (!bss) {
		MAP_ERROR("bss table is not available\n");
		return;
	}

	if (!bss_cfg) {
		MAP_ERROR("bss_cfg of bss "MAP_MACFMT" is not available\n",
			MAP_MACARG(bss->h.mac));
		return;
	}

	blobmsg_add_string(&b, MAP_WDEV_ATTR_NAME_NAME, bss->ifname);

	MAP_DEBUG("bss->band=%d for " MAP_MACFMT "\n", bss->band, MAP_MACARG(bss->h.mac));
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_RF_BANDS_NAME, (1<<bss->band)); /*BAND_2G=0, BAND_5G=1*/
	map_blobmsg_add_mac(MAP_WDEV_ATTR_BSSID_NAME, bss->bssid);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_AUTH_NAME, bss_cfg->auth_mode);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_ENCRYP_NAME, bss_cfg->encrypt);
	if (bss_cfg->ssid)
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_SSID_NAME, bss_cfg->ssid,
				bss_cfg->ssid_len);
	if (bss_cfg->key)
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_WDEV_ATTR_KEY_NAME, bss_cfg->key,
				bss_cfg->key_len);
	if (bss_cfg->mtypes != MAP_BSSCFG_MTYPES_INVALID)
		blobmsg_add_u32(&b, MAP_WDEV_ATTR_MAP_MTYPES_NAME, bss_cfg->mtypes);
}

static int map_get_bsscfgs(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_GET_BSSCFG_MAX];
	void *wdev_array;
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	LIST_HEAD(bsses_head);

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_get_bsscfg_policy, __MAP_GET_BSSCFG_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[MAP_GET_BSSCFG_WIPHY_ID]
		&& blobmsg_len(tb[MAP_GET_BSSCFG_WIPHY_ID]) >= MAP_DEVID_LEN)
		map_blobmsg_get_mac(tb[MAP_GET_BSSCFG_WIPHY_ID], wiphy_id);

	if (tb[MAP_GET_BSSCFG_WDEV_ID]
		&& blobmsg_len(tb[MAP_GET_BSSCFG_WDEV_ID]) >= MAP_DEVID_LEN)
		map_blobmsg_get_mac(tb[MAP_GET_BSSCFG_WDEV_ID], wdev_id);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, MAP_RC_OK);

	wdev_array = blobmsg_open_array(&b, MAP_ATTR_WDEVS_NAME);
	map_find_bsses(&bsses_head, wiphy_id, wdev_id);
	while (!list_empty(&bsses_head)) {
		map_bsscfg_t bss_cfg = {0};
		map_entry_t *entry = list_first_entry(&bsses_head, struct map_entry, lh);
		bss_table_t *bss = (bss_table_t *)entry->stah;
		if (NODE_TYPE_VAP == bss->iftype && BSS_IS_UP(bss)) {
			if (map_extcfg_get_bsscfg((const char *)bss->ifname, &bss_cfg) < 0)
				MAP_WARN("Fail to get_bsscfg on wdev(" MACFMT ")\n", MACARG(wdev_id));
			else {
				void *wdev_tbl = blobmsg_open_table(&b, NULL);
				map_fill_bsscfg(bss, &bss_cfg);
				blobmsg_close_table(&b, wdev_tbl);
			}
		}
		map_free_entry(entry);
	}
	blobmsg_close_array(&b, wdev_array);

	return ubus_send_reply(ctx, req, b.head);
}

static void map_fill_devdata(map_devdata_t *dev_data)
{
	if (dev_data->device_name)
		blobmsg_add_string(&b, MAP_DEVDATA_ATTR_DEVICE_NAME_NAME, dev_data->device_name);
	if (dev_data->manufacturer_name)
		blobmsg_add_string(&b, MAP_DEVDATA_ATTR_MANUFACTURER_NAME_NAME, dev_data->manufacturer_name);
	if (dev_data->model_name)
		blobmsg_add_string(&b, MAP_DEVDATA_ATTR_MODEL_NAME_NAME, dev_data->model_name);
	if (dev_data->model_number)
		blobmsg_add_string(&b, MAP_DEVDATA_ATTR_MODEL_NUMBER_NAME, dev_data->model_number);
	if (dev_data->serial_number)
		blobmsg_add_string(&b, MAP_DEVDATA_ATTR_SERIAL_NUMBER_NAME, dev_data->serial_number);
}

enum {
	MAP_GET_DEVDATA_WDEV_ID = 0,

	__MAP_GET_DEVDATA_MAX
};

static int map_get_devdata(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blob_buf_init(&b, 0);

	map_devdata_t dev_data = {0};
	if (map_extcfg_get_devdata(&dev_data) < 0) {
		MAP_WARN("Fail to get_devdata: call map_extcfg_get_devdata failed\n");
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);
	}

	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, MAP_RC_OK);
	map_fill_devdata(&dev_data);

	return ubus_send_reply(ctx, req, b.head);
}

static void map_fill_wdev_associated(uint8_t *dev_mac,
	uint8_t *peer_mac, uint8_t result)
{
	map_blobmsg_add_mac(MAP_WDEV_ATTR_BSSID_NAME, peer_mac);
	map_blobmsg_add_mac(MAP_WDEV_ATTR_ID_NAME, dev_mac);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_STATUS_NAME, result);
}

enum {
	MAP_GET_STATIONS_WDEV_ID = 0,
	MAP_GET_STATIONS_MAC,

	__MAP_GET_STATIONS_MAX
};

static const struct blobmsg_policy map_get_stations_policy[] = {
	[MAP_GET_STATIONS_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_GET_STATIONS_MAC] = { .name = MAP_ATTR_STA_MAC_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
};

static void map_fill_station(sta_table_t *sta, char *name)
{
	uint32_t age;
	void *station_tbl = blobmsg_open_table(&b, name);

	map_blobmsg_add_mac(MAP_STATION_ATTR_MAC_NAME, sta->h.mac);
	age = map_get_age(sta->assoc_info.last_assoc_ts);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_AGE_NAME, age * 1000);
	if (sta->assoc_info.latest_assoc && sta->assoc_info.latest_assoc_len)
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_STATION_ATTR_ASSOC_REQ_NAME,
			sta->assoc_info.latest_assoc, sta->assoc_info.latest_assoc_len);

	blobmsg_close_table(&b, station_tbl);
}

static int map_get_stations(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_GET_STATIONS_MAX];
	void *station_array;
	uint8_t sta_mac[ETH_ALEN] = { 0 };
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	LIST_HEAD(stas_head);

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_get_stations_policy, __MAP_GET_STATIONS_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (!tb[MAP_GET_STATIONS_WDEV_ID])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	if (blobmsg_len(tb[MAP_GET_STATIONS_WDEV_ID]) < MAP_DEVID_LEN)
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	map_blobmsg_get_mac(tb[MAP_GET_STATIONS_WDEV_ID], wdev_id);

	if (tb[MAP_GET_STATIONS_MAC]
		&& blobmsg_len(tb[MAP_GET_STATIONS_MAC]) >= MAP_DEVID_LEN)
		map_blobmsg_get_mac(tb[MAP_GET_STATIONS_MAC], sta_mac);

	map_find_staes_with_bssid(&stas_head, sta_mac, wdev_id);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, MAP_RC_OK);
	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, wdev_id);

	station_array = blobmsg_open_array(&b, MAP_ATTR_STATIONS_NAME);

	while (!list_empty(&stas_head)) {
		map_entry_t *entry = list_first_entry(&stas_head, struct map_entry, lh);

		map_fill_station((sta_table_t *)(entry->stah), NULL);
		map_free_entry(entry);
	}

	blobmsg_close_array(&b, station_array);

	return ubus_send_reply(ctx, req, b.head);
}

enum {
	MAP_DEL_STATION_WDEV_ID = 0,
	MAP_DEL_STATION_MAC,
	MAP_DEL_STATION_SUBTYPE,
	MAP_DEL_STATION_REASON,

	__MAP_DEL_STATION_MAX
};

static const struct blobmsg_policy map_del_station_policy[] = {
	[MAP_DEL_STATION_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_DEL_STATION_MAC] = { .name = MAP_ATTR_STA_MAC_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_DEL_STATION_SUBTYPE] = { .name = MAP_ATTR_MGMT_SUBTYPE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_DEL_STATION_REASON] = { .name = MAP_ATTR_REASON_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int map_del_station(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_DEL_STATION_MAX];
	uint8_t sta_mac[ETH_ALEN] = { 0 };
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	int is_deauth = 1;
	uint16_t reason = MAP_DEAUTH_CODE_DEFAULT;
	LIST_HEAD(stas_head);

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_del_station_policy, __MAP_DEL_STATION_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (!tb[MAP_DEL_STATION_WDEV_ID]
		|| !tb[MAP_DEL_STATION_MAC])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	if (blobmsg_len(tb[MAP_DEL_STATION_WDEV_ID]) < MAP_DEVID_LEN
		|| blobmsg_len(tb[MAP_DEL_STATION_MAC]) < MAP_DEVID_LEN)
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	if (tb[MAP_DEL_STATION_SUBTYPE]
		&& (IEEE80211_FC0_SUBTYPE_DISASSOC
			== blobmsg_get_u32(tb[MAP_DEL_STATION_SUBTYPE])))
		is_deauth = 0;

	if (tb[MAP_DEL_STATION_REASON])
		reason = blobmsg_get_u32(tb[MAP_DEL_STATION_REASON]);

	if (!reason)
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	map_blobmsg_get_mac(tb[MAP_DEL_STATION_WDEV_ID], wdev_id);
	map_blobmsg_get_mac(tb[MAP_DEL_STATION_MAC], sta_mac);

	if (map_deauth_sta(wdev_id, sta_mac, is_deauth, reason) < 0)
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);

	return map_method_successed(ctx, req, method);
}

enum {
	MAP_FILTER_STATION_WDEV_ID = 0,
	MAP_FILTER_STATION_MAC,
	MAP_FILTER_STATION_TABLE,

	__MAP_FILTER_STATION_MAX
};

static const struct blobmsg_policy map_filter_station_policy[] = {
	[MAP_FILTER_STATION_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_FILTER_STATION_MAC] = { .name = MAP_ATTR_STA_MAC_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_FILTER_STATION_TABLE] = { .name = MAP_ATTR_FILTER_NAME, .type = BLOBMSG_TYPE_TABLE},
};

static const struct blobmsg_policy map_filter_policy[NUM_MAP_FILTER_ATTRS] = {
	[MAP_FILTER_ATTR_MODE] = { .name = MAP_FILTER_ATTR_MODE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_FILTER_ATTR_RSSI] = { .name = MAP_FILTER_ATTR_RSSI_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_FILTER_ATTR_MASK] = { .name = MAP_FILTER_ATTR_MASK_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_FILTER_ATTR_DURATION] = { .name = MAP_FILTER_ATTR_DURATION_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_FILTER_ATTR_REJECT] = { .name = MAP_FILTER_ATTR_REJECT_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_FILTER_ATTR_IES] = { .name = MAP_FILTER_ATTR_IES_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static struct list_head map_sta_filter_timeouts = LIST_HEAD_INIT(map_sta_filter_timeouts);

map_sta_filter_timeout_entry_t * map_find_sta_filter_timer_entry(void *value,
	int comp_type)
{
	map_sta_filter_timeout_entry_t *timeout_entry = NULL;
	int is_found = 0;

	list_for_each_entry(timeout_entry, &map_sta_filter_timeouts, lh) {
		if (comp_type == MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_TIMEOUT &&
			(struct uloop_timeout *)value == timeout_entry->timeout) {
			is_found = 1;
			break;
		}
		else if (comp_type == MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_STA_MAC &&
			MAP_MAC_EQ(timeout_entry->sta_id, (uint8_t *)value)) {
			is_found = 1;
			break;
		}
	}

	if (!is_found)
		return NULL;

	return timeout_entry;
}

void map_del_sta_filter_timer_entry(uint8_t *sta)
{
	map_sta_filter_timeout_entry_t *timeout_entry;

	timeout_entry = map_find_sta_filter_timer_entry(sta,
		MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_STA_MAC);

	if (timeout_entry) {
		MAP_FREE(timeout_entry->timeout);
		list_del(&timeout_entry->lh);
		MAP_FREE(timeout_entry);
	}
}

void map_sta_filter_timer_expire(struct uloop_timeout *timeout)
{
	map_sta_filter_timeout_entry_t *timeout_entry;

	timeout_entry = map_find_sta_filter_timer_entry(timeout,
		MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_TIMEOUT);

	if (timeout_entry) {
		map_del_sta_filter_rule(timeout_entry->dev_id, timeout_entry->sta_id);
		MAP_FREE(timeout_entry->timeout);
		list_del(&timeout_entry->lh);
		MAP_FREE(timeout_entry);
	}
}

int map_activate_sta_filter_rule_timer(uint8_t *dev_id, uint8_t *sta_id,
	uint8_t rssi_mode, int8_t rssi, uint32_t mask, uint32_t duration,
	uint16_t reject_mode, uint8_t *reject_payload, uint16_t reject_payload_len)
{
	map_sta_filter_timeout_entry_t *map_sta_filter_timeout_entry = NULL;
	struct uloop_timeout *timeout;

	map_sta_filter_timeout_entry = map_find_sta_filter_timer_entry(sta_id,
		MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_STA_MAC);

	if (!map_sta_filter_timeout_entry) {
		map_sta_filter_timeout_entry = MAP_CALLOC(1, sizeof(map_sta_filter_timeout_entry_t));
		if (NULL == map_sta_filter_timeout_entry)
			return -1;
		timeout = MAP_CALLOC(1, sizeof(struct uloop_timeout));
		if (NULL == timeout)
			return -1;

		timeout->cb = map_sta_filter_timer_expire;
		map_sta_filter_timeout_entry->timeout = timeout;
		MAP_MAC_COPY(map_sta_filter_timeout_entry->dev_id, dev_id);
		MAP_MAC_COPY(map_sta_filter_timeout_entry->sta_id, sta_id);
		list_add_tail(&map_sta_filter_timeout_entry->lh, &map_sta_filter_timeouts);
	} else {
		uloop_timeout_cancel(map_sta_filter_timeout_entry->timeout);
		MAP_FREE(map_sta_filter_timeout_entry->timeout);
		map_sta_filter_timeout_entry->timeout = NULL;

		timeout = MAP_CALLOC(1, sizeof(struct uloop_timeout));
		if (NULL == timeout)
			return -1;

		timeout->cb = map_sta_filter_timer_expire;
		map_sta_filter_timeout_entry->timeout = timeout;
		MAP_MAC_COPY(map_sta_filter_timeout_entry->dev_id, dev_id);
	}

	uloop_timeout_set(map_sta_filter_timeout_entry->timeout, duration * 1000);

	return map_add_sta_filter_rule(dev_id, sta_id, rssi_mode, rssi, mask,
			reject_mode, reject_payload, reject_payload_len);
}

static int map_filter_rule_apply(uint8_t *dev_id, uint8_t *sta,
	struct blob_attr **filter_tb, int is_defined)
{
	uint8_t rssi_mode = 0, *reject_payload = NULL;
	int8_t rssi = 0, ret;
	uint16_t reject_mode = 0, reject_payload_len = 0;
	uint32_t duration = 0xffffffff, mask = 0;

	if (is_defined) {
		if (filter_tb[MAP_FILTER_ATTR_MODE])
			rssi_mode = (uint8_t)blobmsg_get_u32(filter_tb[MAP_FILTER_ATTR_MODE]);

		if (filter_tb[MAP_FILTER_ATTR_RSSI])
			rssi = (int8_t)blobmsg_get_u32(filter_tb[MAP_FILTER_ATTR_RSSI]);

		if (filter_tb[MAP_FILTER_ATTR_MASK])
			mask = blobmsg_get_u32(filter_tb[MAP_FILTER_ATTR_MASK]);

		if (filter_tb[MAP_FILTER_ATTR_DURATION])
			duration = blobmsg_get_u32(filter_tb[MAP_FILTER_ATTR_DURATION]);

		if (filter_tb[MAP_FILTER_ATTR_REJECT])
			reject_mode = (uint16_t)blobmsg_get_u32(filter_tb[MAP_FILTER_ATTR_REJECT]);

		if (filter_tb[MAP_FILTER_ATTR_IES]) {
			reject_payload = (uint8_t *)blobmsg_data(filter_tb[MAP_FILTER_ATTR_IES]);
			reject_payload_len = blobmsg_data_len(filter_tb[MAP_FILTER_ATTR_IES]);
		}
	}

	if (duration == 0xffffffff || duration == 0)
		map_del_sta_filter_timer_entry(sta);

	if (duration == 0xffffffff)
		ret = map_add_sta_filter_rule(dev_id, sta, rssi_mode, rssi, mask,
			reject_mode, reject_payload, reject_payload_len);
	else if (duration == 0)
		ret = map_del_sta_filter_rule(dev_id, sta);
	else
		ret = map_activate_sta_filter_rule_timer(dev_id, sta, rssi_mode, rssi,
			mask, duration, reject_mode, reject_payload, reject_payload_len);

	return ret;
}

static int map_filter_station(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_FILTER_STATION_MAX];
	struct blob_attr *param_tb[NUM_MAP_FILTER_ATTRS];
	uint8_t wdev_id[ETH_ALEN] = { 0 },
			sta_mac[ETH_ALEN] = { 0 };
	int filter_table_defined = 0;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_filter_station_policy, __MAP_FILTER_STATION_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_FILTER_STATION_WDEV_ID]
		|| !tb[MAP_FILTER_STATION_MAC])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(tb[MAP_FILTER_STATION_WDEV_ID], wdev_id);
	map_blobmsg_get_mac(tb[MAP_FILTER_STATION_MAC], sta_mac);

	if (tb[MAP_FILTER_STATION_TABLE]) {
		blobmsg_parse(map_filter_policy, NUM_MAP_FILTER_ATTRS, param_tb,
			blobmsg_data(tb[MAP_FILTER_STATION_TABLE]), blobmsg_len(tb[MAP_FILTER_STATION_TABLE]));
		filter_table_defined = 1;
	}

	if (map_filter_rule_apply(wdev_id, sta_mac, param_tb, filter_table_defined) < 0)
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);

	return map_method_successed(ctx, req, method);
}

enum {
	MAP_REG_FRAME_WDEV_ID = 0,
	MAP_REG_FRAME_RX,
	MAP_REG_FRAME_SUBTYPE,
	MAP_REG_FRAME_MATCH,

	__MAP_REG_FRAME_MAX
};

static const struct blobmsg_policy map_reg_frame_policy[] = {
	[MAP_REG_FRAME_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_REG_FRAME_RX] = { .name = MAP_ATTR_FRAME_RX_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_REG_FRAME_SUBTYPE] = { .name = MAP_ATTR_MGMT_SUBTYPE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_REG_FRAME_MATCH] = { .name = MAP_ATTR_FRAME_MATCH_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static uint32_t map_reg_frame_to_bss(uint8_t *wdev_id, uint8_t subtype,
	uint8_t *match, uint32_t match_len, uint32_t rx_mode)
{
	bss_table_t *bss = map_get_stadb_bss(wdev_id);

	if (!bss)
		return MAP_RC_INVALID_VALUE;

	if (!map_check_frame_registrable(bss, (rx_mode >= __MAP_FRAME_RX_LAST) ? 0 : 1,
			subtype, match, match_len)) {
		MAP_INFO("Do not support register the management(%02x) on "
			MAP_MACFMT "\n", subtype, MAP_MACARG(wdev_id));
		return MAP_RC_NOT_SUPPORTED;
	}

	map_send_frame_reg_rpe(bss, subtype, match, match_len, rx_mode);

	map_stadb_stah_unref((stah_t *)bss);
	return MAP_RC_OK;
}

static int map_reg_frame(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_REG_FRAME_MAX];
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	uint32_t match_len = 0, rx_mode = __MAP_FRAME_RX_LAST;
	uint8_t subtype, *match = NULL;
	uint32_t rc;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_reg_frame_policy, __MAP_REG_FRAME_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_REG_FRAME_WDEV_ID]
		|| !tb[MAP_REG_FRAME_SUBTYPE])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(tb[MAP_REG_FRAME_WDEV_ID], wdev_id);
	subtype = (uint8_t)blobmsg_get_u32(tb[MAP_REG_FRAME_SUBTYPE]);

	if (tb[MAP_REG_FRAME_RX])
		rx_mode = blobmsg_get_u32(tb[MAP_REG_FRAME_RX]);
	if (tb[MAP_REG_FRAME_MATCH]) {
		match = (uint8_t *)blobmsg_data(tb[MAP_REG_FRAME_MATCH]);
		match_len = blobmsg_len(tb[MAP_REG_FRAME_MATCH]);
	}

	rc = map_reg_frame_to_bss(wdev_id, subtype, match, match_len, rx_mode);
	if (rc)
		return map_method_failed(ctx, req, method, rc);
	else
		return map_method_successed(ctx, req, method);
}

enum {
	MAP_SEND_FRAME_WDEV_ID = 0,
	MAP_SEND_FRAME_FRAME,

	__MAP_SEND_FRAME_MAX
};

static const struct blobmsg_policy map_send_frame_policy[] = {
	[MAP_SEND_FRAME_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_SEND_FRAME_FRAME] = { .name = MAP_ATTR_FRAME_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static int map_send_frame(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_SEND_FRAME_MAX];
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	uint8_t *frame = NULL;
	uint16_t frame_len;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_send_frame_policy, __MAP_SEND_FRAME_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_SEND_FRAME_WDEV_ID] || !tb[MAP_SEND_FRAME_FRAME])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	frame_len = blobmsg_len(tb[MAP_SEND_FRAME_FRAME]);
	if (frame_len <= sizeof(struct ieee80211_frame))
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	frame = (uint8_t *)blobmsg_data(tb[MAP_SEND_FRAME_FRAME]);
	map_blobmsg_get_mac(tb[MAP_SEND_FRAME_WDEV_ID], wdev_id);

	map_send_frame_to_rpe(wdev_id, frame, frame_len);

	return map_method_successed(ctx, req, method);
}

static void map_fill_frame_received(uint8_t *dev_mac,
	uint8_t *frame, uint16_t frame_len)
{
	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, dev_mac);
	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_ATTR_FRAME_NAME, frame, frame_len);
}

static void map_fill_rssi_adv(uint8_t *rssi_adv)
{
	blobmsg_add_u32(&b, MAP_ATTR_RSSI_NAME, (int32_t)((int8_t)*rssi_adv));
	blobmsg_add_u32(&b, MAP_ATTR_CHANNEL_NAME, *(rssi_adv+2));
	blobmsg_add_u32(&b, MAP_ATTR_WITHHOLD_NAME, *(rssi_adv+3));
}

enum {
	MAP_MON_CHAN_ID = 0,
	MAP_MON_CHAN_OPCLASS,
	MAP_MON_CHAN_CHAN,

	__MAP_MON_CHAN_MAX
};

static const struct blobmsg_policy map_monitor_chan_policy[] = {
	[MAP_MON_CHAN_ID] = { .name = MAP_WIPHY_ATTR_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_MON_CHAN_OPCLASS] = { .name = MAP_WIPHY_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_MON_CHAN_CHAN] = { .name = MAP_WIPHY_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int map_monitor_chan(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_MON_CHAN_MAX];
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	uint8_t chan = 0, opclass = 0;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_monitor_chan_policy, __MAP_MON_CHAN_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_MON_CHAN_ID])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(tb[MAP_MON_CHAN_ID], wiphy_id);

	if (tb[MAP_MON_CHAN_OPCLASS])
		opclass = blobmsg_get_u32(tb[MAP_MON_CHAN_OPCLASS]);

	if (tb[MAP_MON_CHAN_CHAN])
		chan = blobmsg_get_u32(tb[MAP_MON_CHAN_CHAN]);

	map_set_intf_mon_chan_conf(wiphy_id, opclass, chan);

	return map_method_successed(ctx, req, method);
}

enum {
	MAP_ROAM_WDEV_ID = 0,
	MAP_ROAM_WDEV_TARGET,
	MAP_ROAM_WDEV_OPCLASS,
	MAP_ROAM_WDEV_CHAN,

	__MAP_ROAM_WDEV_MAX
};

static const struct blobmsg_policy map_roam_wdev_policy[] = {
	[MAP_ROAM_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_ROAM_WDEV_TARGET] = { .name = MAP_ATTR_ROAM_TARGET_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_ROAM_WDEV_OPCLASS] = { .name = MAP_WDEV_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_ROAM_WDEV_CHAN] = { .name = MAP_WDEV_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int map_roam_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_ROAM_WDEV_MAX];
	uint8_t wdev_id[ETH_ALEN] = { 0 },
			target_id[ETH_ALEN] = { 0 };
	int ch = 0, opclass = 0;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_roam_wdev_policy, __MAP_ROAM_WDEV_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_ROAM_WDEV_ID] || !tb[MAP_ROAM_WDEV_TARGET])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(tb[MAP_ROAM_WDEV_ID], wdev_id);
	map_blobmsg_get_mac(tb[MAP_ROAM_WDEV_TARGET], target_id);

	if (MAP_MAC_IS_NULL(wdev_id) || MAP_MAC_IS_NULL(target_id))
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	if (tb[MAP_ROAM_WDEV_OPCLASS])
		opclass = blobmsg_get_u32(tb[MAP_ROAM_WDEV_OPCLASS]);

	if (tb[MAP_ROAM_WDEV_CHAN])
		ch = blobmsg_get_u32(tb[MAP_ROAM_WDEV_CHAN]);

	if (map_roam_wdev_to_target_bss(wdev_id, target_id, ch, opclass) < 0)
		return map_method_failed(ctx, req, method, MAP_RC_UNKNOWN_ERROR);

	return map_method_successed(ctx, req, method);
}

static const struct ubus_method map_mlme_methods[] = {
	UBUS_METHOD(MAP_METHOD_CONFIG_WIPHY_NAME, map_config_wiphy, map_wiphy_policy),
	UBUS_METHOD(MAP_METHOD_CREATE_WDEV_NAME, map_create_wdev, map_wdev_policy),
	UBUS_METHOD(MAP_METHOD_DELETE_WDEV_NAME, map_delete_wdev, map_wdev_policy),
	UBUS_METHOD(MAP_METHOD_CONFIG_WDEV_NAME, map_config_wdev, map_wdev_policy),
	UBUS_METHOD(MAP_METHOD_START_WPS_NAME, map_start_wps, map_start_wps_policy),
	UBUS_METHOD(MAP_METHOD_GET_BSSCFGS_NAME, map_get_bsscfgs, map_get_bsscfg_policy),
	UBUS_METHOD_NOARG(MAP_METHOD_GET_DEVDATA_NAME, map_get_devdata),
	UBUS_METHOD(MAP_METHOD_GET_STATIONS_NAME, map_get_stations, map_get_stations_policy),
	UBUS_METHOD(MAP_METHOD_DEL_STATION_NAME, map_del_station, map_del_station_policy),
	UBUS_METHOD(MAP_METHOD_FILTER_STATION_NAME, map_filter_station, map_filter_station_policy),
	UBUS_METHOD(MAP_METHOD_REG_FRAME_NAME, map_reg_frame, map_reg_frame_policy),
	UBUS_METHOD(MAP_METHOD_SEND_FRAME_NAME, map_send_frame, map_send_frame_policy),
	UBUS_METHOD(MAP_METHOD_MONITOR_CHAN_NAME, map_monitor_chan, map_monitor_chan_policy),
	UBUS_METHOD(MAP_METHOD_ROAM_WDEV_NAME, map_roam_wdev, map_roam_wdev_policy),
};

static struct ubus_object_type map_mlme_obj_type =
	UBUS_OBJECT_TYPE(MAP_MLME_OBJ_NAME, map_mlme_methods);

static struct ubus_object map_mlme_obj = {
	.name = MAP_MLME_OBJ_NAME,
	.type = &map_mlme_obj_type,
	.methods = map_mlme_methods,
	.n_methods = ARRAY_SIZE(map_mlme_methods),
};

enum {
	MAP_SET_PERIODS_WDEV_ID = 0,
	MAP_SET_PERIODS_TABLE,

	__MAP_SET_PERIODS_MAX
};

static const struct blobmsg_policy map_set_periods_policy[] = {
	[MAP_SET_PERIODS_WDEV_ID] = { .name = MAP_ATTR_WDEV_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_SET_PERIODS_TABLE] = { .name = MAP_ATTR_STATS_PERIODS_NAME, .type = BLOBMSG_TYPE_TABLE},
};

static const struct blobmsg_policy map_stats_period_policy[NUM_MAP_STATS_ATTRS] = {
	MAP_ATTRS_POLICY_INIT(MAP_STATS_ATTR_WDEV, BLOBMSG_TYPE_INT32),
	MAP_ATTRS_POLICY_INIT(MAP_STATS_ATTR_STA, BLOBMSG_TYPE_INT32),
	MAP_ATTRS_POLICY_INIT(MAP_STATS_ATTR_MONITOR, BLOBMSG_TYPE_INT32),
};

static struct list_head map_timeouts = LIST_HEAD_INIT(map_timeouts);

static void map_fill_espi(espi_t *espi, int ac, int eatf)
{
	void *espi_tbl = blobmsg_open_table(&b, NULL);

	blobmsg_add_u32(&b, MAP_ESPI_ATTR_AC_NAME, ac);
	blobmsg_add_u32(&b, MAP_ESPI_ATTR_FORMAT_NAME, espi->format);
	blobmsg_add_u32(&b, MAP_ESPI_ATTR_BA_SIZE_NAME, espi->window);
	blobmsg_add_u32(&b, MAP_ESPI_ATTR_EST_AIRTIME_NAME, eatf);
	blobmsg_add_u32(&b, MAP_ESPI_ATTR_PPDU_DUR_NAME, espi->duration);

	blobmsg_close_table(&b, espi_tbl);
}

static void map_fill_espis(espi_t *espis, int eatf)
{
	void *espis_array;
	uint8_t i;

	espis_array = blobmsg_open_array(&b, MAP_WDEV_ATTR_ESPI_NAME);

	for (i = 0; i < AC_MAXNUM; i++)
		map_fill_espi(espis + i, i, eatf);

	blobmsg_close_array(&b, espis_array);
}

static void map_fill_wdev_stats_updated(bss_table_t *bss)
{
	int eatf;

	if (!bss) {
		MAP_ERROR("bss table is not available\n");
		return;
	}

	map_blobmsg_add_mac(MAP_WDEV_ATTR_ID_NAME, bss->h.mac);
	blobmsg_add_u32(&b, MAP_WDEV_ATTR_FAT_NAME, bss->fat);

	eatf = map_get_bss_eatf(bss);
	map_fill_espis(bss->espis, eatf);
}

static void map_fill_sta_stats(sta_table_t *sta)
{
	void *sta_stats_tbl;
	timestamp_t now = csm_get_timestamp();

	if (!sta) {
		MAP_ERROR("sta table is not available\n");
		return;
	}

	sta_stats_tbl = blobmsg_open_table(&b, NULL);

	map_blobmsg_add_mac(MAP_STATION_ATTR_MAC_NAME, sta->h.mac);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RSSI_NAME, sta->assoc_info.last_rssi);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RATE_DOWNLINK_NAME, sta->assoc_info.avg_tx_phyrate);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_AGE_DOWNLINK_NAME, (int32_t)((now - sta->assoc_info.last_tx_ts) * 1000));
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RATE_UPLINK_NAME, sta->assoc_info.avg_rx_phyrate);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_AGE_UPLINK_NAME, (int32_t)((now - sta->assoc_info.last_rx_ts) * 1000));
	blobmsg_add_u32(&b, MAP_STATION_ATTR_TX_BYTES_NAME, sta->assoc_info.stats.tx_bytes);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RX_BYTES_NAME, sta->assoc_info.stats.rx_bytes);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_TX_PACKETS_NAME, sta->assoc_info.stats.tx_packets);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RX_PACKETS_NAME, sta->assoc_info.stats.rx_packets);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_TX_ERRORS_NAME, sta->assoc_info.stats.tx_errors);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RX_ERRORS_NAME, sta->assoc_info.stats.rx_errors);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_TX_RETRIES_NAME, sta->assoc_info.stats.tx_tries);

	blobmsg_close_table(&b, sta_stats_tbl);
}

static void map_fill_non_assoc_sta_stats(sta_table_t *sta,
	uint8_t *mac, uint8_t opclass)
{
	void *non_assoc_sta_stats_tbl;
	sta_seen_bssid_t *seen_bssid = NULL;
	timestamp_t now = csm_get_timestamp();

	if (!sta) {
		MAP_ERROR("sta table is not available\n");
		return;
	}

	seen_bssid = map_find_seenbssid(sta, mac);
	if (!seen_bssid)
		return;

	non_assoc_sta_stats_tbl = blobmsg_open_table(&b, NULL);

	map_blobmsg_add_mac(MAP_STATION_ATTR_MAC_NAME, sta->h.mac);
	/* assuming the opclass of unassociated sta is same as VAP */
	blobmsg_add_u32(&b, MAP_STATION_ATTR_OPCLASS_NAME, opclass);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_CHANNEL_NAME, seen_bssid->ch);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_RSSI_NAME, seen_bssid->last_rssi);
	blobmsg_add_u32(&b, MAP_STATION_ATTR_AGE_NAME, (int32_t)((now - seen_bssid->last_ts) * 1000));

	blobmsg_close_table(&b, non_assoc_sta_stats_tbl);
}

static void map_fill_stas_stats_updated(uint8_t *mac)
{
	map_entry_t *entry;
	void *stas_stats_array;
	LIST_HEAD(stas_head);

	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, mac);

	map_find_staes_with_bssid(&stas_head, NULL, mac);

	stas_stats_array = blobmsg_open_array(&b, MAP_ATTR_STATIONS_NAME);
	while (!list_empty(&stas_head)) {
		entry = list_first_entry(&stas_head, struct map_entry, lh);
		map_fill_sta_stats((sta_table_t *)(entry->stah));
		map_free_entry(entry);
	}

	blobmsg_close_array(&b, stas_stats_array);
}

static void map_fill_mon_stats_updated(uint8_t *mac, uint8_t opclass)
{
	map_entry_t *entry;
	void *stas_stats_array;
	LIST_HEAD(non_assoc_stas_head);

	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, mac);

	map_find_non_assoc_staes(&non_assoc_stas_head);

	stas_stats_array = blobmsg_open_array(&b, MAP_ATTR_STATIONS_NAME);
	while (!list_empty(&non_assoc_stas_head)) {
		entry = list_first_entry(&non_assoc_stas_head, struct map_entry, lh);
		map_fill_non_assoc_sta_stats((sta_table_t *)(entry->stah), mac,
			opclass);
		map_free_entry(entry);
	}

	blobmsg_close_array(&b, stas_stats_array);
}

void map_wdev_stats_fat_updated_timer(struct uloop_timeout *timeout)
{
	map_wdev_timeout_entry_t *timeout_entry;
	int is_found = 0;
	map_event_t map_event;

	list_for_each_entry(timeout_entry, &map_timeouts, lh) {
		if (timeout == timeout_entry->timeout[MAP_STATS_ATTR_WDEV]) {
			is_found = 1;
			break;
		}
	}

	if (is_found) {
		uloop_timeout_set(timeout_entry->timeout[MAP_STATS_ATTR_WDEV],
			timeout_entry->fat_period * 1000);
		MAP_MAC_COPY(map_event.dev_id, timeout_entry->dev_id);
		map_event.id = MAP_EVENT_WDEV_STATS_UPDATED;
		map_send_event(&map_event);
	}
}

void map_wdev_stats_sta_updated_timer(struct uloop_timeout *timeout)
{
	map_wdev_timeout_entry_t *timeout_entry;
	int is_found = 0;
	map_event_t map_event;

	list_for_each_entry(timeout_entry, &map_timeouts, lh) {
		if (timeout == timeout_entry->timeout[MAP_STATS_ATTR_STA]) {
			is_found = 1;
			break;
		}
	}

	if (is_found) {
		uloop_timeout_set(timeout_entry->timeout[MAP_STATS_ATTR_STA],
			timeout_entry->sta_period * 1000);
		MAP_MAC_COPY(map_event.dev_id, timeout_entry->dev_id);
		map_event.id = MAP_EVENT_STA_STATS_UPDATED;
		map_send_event(&map_event);
	}
}

void map_wdev_stats_mon_updated_timer(struct uloop_timeout *timeout)
{
	map_wdev_timeout_entry_t *timeout_entry;
	int is_found = 0;
	map_event_t map_event;

	list_for_each_entry(timeout_entry, &map_timeouts, lh) {
		if (timeout == timeout_entry->timeout[MAP_STATS_ATTR_MONITOR]) {
			is_found = 1;
			break;
		}
	}
	if (is_found) {
		uloop_timeout_set(timeout_entry->timeout[MAP_STATS_ATTR_MONITOR],
			timeout_entry->mon_period * 1000);
		MAP_MAC_COPY(map_event.dev_id, timeout_entry->dev_id);
		map_event.id = MAP_EVENT_MON_STATS_UPDATED;
		map_send_event(&map_event);
	}
}

void map_del_timer(uint8_t *mac, uint32_t period, uint8_t timer_idx)
{
	int is_found = 0;
	map_wdev_timeout_entry_t *map_timeout_entry;

	list_for_each_entry(map_timeout_entry, &map_timeouts, lh) {
		if (MAP_MAC_EQ(map_timeout_entry->dev_id, mac)) {
			is_found = 1;
			break;
		}
	}

	if (!is_found)
		return;

	if (map_timeout_entry->timeout[timer_idx]) {
		uloop_timeout_cancel(map_timeout_entry->timeout[timer_idx]);
		MAP_FREE(map_timeout_entry->timeout[timer_idx]);
		map_timeout_entry->timeout[timer_idx] = NULL;
	}

	if (!map_timeout_entry->timeout[MAP_STATS_ATTR_WDEV] &&
		!map_timeout_entry->timeout[MAP_STATS_ATTR_STA] &&
		!map_timeout_entry->timeout[MAP_STATS_ATTR_MONITOR]) {
		list_del(&map_timeout_entry->lh);
		MAP_FREE(map_timeout_entry);
	}

}

void map_add_or_update_timer(uint8_t *mac, uint32_t period, uint8_t timer_idx)
{
	int is_found = 0;
	map_wdev_timeout_entry_t *map_timeout_entry = NULL;
	struct uloop_timeout *timeout = NULL;
	static void (*pf[3])(struct uloop_timeout *timeout) = {map_wdev_stats_fat_updated_timer,
		map_wdev_stats_sta_updated_timer, map_wdev_stats_mon_updated_timer};

	list_for_each_entry(map_timeout_entry, &map_timeouts, lh) {
		if (MAP_MAC_EQ(map_timeout_entry->dev_id, mac)) {
			is_found = 1;
			break;
		}
	}

	if (!is_found) {
		map_timeout_entry = (map_wdev_timeout_entry_t *)
			MAP_CALLOC(1, sizeof(map_wdev_timeout_entry_t));
		if (NULL == map_timeout_entry)
			return;
		timeout = (struct uloop_timeout *)
			MAP_CALLOC(1, sizeof(struct uloop_timeout));
		if (NULL == timeout) {
			MAP_FREE(map_timeout_entry);
			return;
		}

		timeout->cb = pf[timer_idx];
		map_timeout_entry->timeout[timer_idx] = timeout;
		MAP_MAC_COPY(map_timeout_entry->dev_id, mac);
		list_add_tail(&map_timeout_entry->lh, &map_timeouts);
	}

	if (!map_timeout_entry->timeout[timer_idx]) {
		timeout = (struct uloop_timeout *)
			MAP_CALLOC(1, sizeof(struct uloop_timeout));
		if (NULL == timeout)
			return;
		timeout->cb = pf[timer_idx];
		map_timeout_entry->timeout[timer_idx] = timeout;
	}

	if (MAP_STATS_ATTR_WDEV == timer_idx)
		map_timeout_entry->fat_period = period;
	else if (MAP_STATS_ATTR_STA == timer_idx)
		map_timeout_entry->sta_period = period;
	else if (MAP_STATS_ATTR_MONITOR == timer_idx)
		map_timeout_entry->mon_period = period;
	uloop_timeout_set(map_timeout_entry->timeout[timer_idx], period * 1000);
}

void map_set_period(uint8_t *wdev_mac, struct blob_attr **periods)
{
	int period;

	if (!periods)
		return;

	if (periods[MAP_STATS_ATTR_WDEV]) {
		period = blobmsg_get_u32(periods[MAP_STATS_ATTR_WDEV]);

		if (!period)
			map_del_timer(wdev_mac, period, MAP_STATS_ATTR_WDEV);
		else
			map_add_or_update_timer(wdev_mac, period, MAP_STATS_ATTR_WDEV);
	}

	if (periods[MAP_STATS_ATTR_STA]) {
		period = blobmsg_get_u32(periods[MAP_STATS_ATTR_STA]);

		if (!period)
			map_del_timer(wdev_mac, period, MAP_STATS_ATTR_STA);
		else
			map_add_or_update_timer(wdev_mac, period, MAP_STATS_ATTR_STA);
	}

	if (periods[MAP_STATS_ATTR_MONITOR]) {
		period = blobmsg_get_u32(periods[MAP_STATS_ATTR_MONITOR]);

		if (!period)
			map_del_timer(wdev_mac, period, MAP_STATS_ATTR_MONITOR);
		else
			map_add_or_update_timer(wdev_mac, period, MAP_STATS_ATTR_MONITOR);
	}
}

static int map_set_periods(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_SET_PERIODS_MAX];
	struct blob_attr *param_tb[NUM_MAP_STATS_ATTRS];
	uint8_t wdev_id[ETH_ALEN] = { 0 };

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_set_periods_policy, __MAP_SET_PERIODS_MAX,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_SET_PERIODS_WDEV_ID]
		|| !tb[MAP_SET_PERIODS_TABLE])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(tb[MAP_SET_PERIODS_WDEV_ID], wdev_id);

	blobmsg_parse(map_stats_period_policy, NUM_MAP_STATS_ATTRS, param_tb,
		blobmsg_data(tb[MAP_SET_PERIODS_TABLE]), blobmsg_len(tb[MAP_SET_PERIODS_TABLE]));

	map_set_period(wdev_id, param_tb);

	return map_method_successed(ctx, req, method);
}

enum {
	MAP_GET_MONITOR_STATS_WIPHY_ID = 0,
	MAP_GET_MONITOR_STATS_STATIONS,

	__MAP_GET_MONITOR_STATS_MAX
};

static const struct blobmsg_policy map_get_monitor_stats_policy[] = {
	[MAP_GET_MONITOR_STATS_WIPHY_ID] = { .name = MAP_ATTR_WIPHY_ID_NAME, .type = MAP_BLOBMSG_TYPE_MAC },
	[MAP_GET_MONITOR_STATS_STATIONS] = { .name = MAP_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int map_get_monitor_stats(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_GET_MONITOR_STATS_MAX];
	uint8_t wiphy_id[ETH_ALEN] = { 0 };
	uint8_t wdev_id[ETH_ALEN] = { 0 };
	void *stas_stats_array;
	radio_table_t *radio;
	bss_table_t *first_bss, *bss;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_get_monitor_stats_policy, __MAP_GET_MONITOR_STATS_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (!tb[MAP_GET_MONITOR_STATS_WIPHY_ID])
		return map_method_failed(ctx, req, method, MAP_RC_MISS_ARGUMENT);

	map_blobmsg_get_mac(tb[MAP_GET_MONITOR_STATS_WIPHY_ID], wiphy_id);
	radio = map_get_stadb_radio(wiphy_id);
	if (!radio)
		return map_method_failed(ctx, req, method, MAP_RC_INVALID_VALUE);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, MAP_ATTR_RC_NAME, MAP_RC_OK);
	map_blobmsg_add_mac(MAP_ATTR_WIPHY_ID_NAME, wiphy_id);

	stas_stats_array = blobmsg_open_array(&b, MAP_ATTR_STATIONS_NAME);
	first_bss = map_get_radio_first_bss(radio);
	if (first_bss->iftype == NODE_TYPE_STA) {
		bss = map_get_radio_first_vap_in_repeater(radio);
		MAP_MAC_COPY(wdev_id, bss->bssid);
		map_stadb_stah_unref(bss);
	} else
		MAP_MAC_COPY(wdev_id, first_bss->bssid);
	map_stadb_stah_unref(first_bss);
	if (!tb[MAP_GET_MONITOR_STATS_STATIONS]) {
		LIST_HEAD(non_assoc_stas_head);
		map_find_non_assoc_staes(&non_assoc_stas_head);

		while (!list_empty(&non_assoc_stas_head)) {
			map_entry_t *entry = list_first_entry(&non_assoc_stas_head, struct map_entry, lh);
			map_fill_non_assoc_sta_stats((sta_table_t *)(entry->stah), wdev_id,
				radio->opclass);
			map_free_entry(entry);
		}
	} else {
		struct blob_attr *attr;
		int rem;
		blobmsg_for_each_attr(attr, tb[MAP_GET_MONITOR_STATS_STATIONS], rem) {
			uint8_t mac[ETH_ALEN] = { 0 };
			sta_table_t *sta;

			map_blobmsg_get_mac(attr, mac);
			sta = map_get_stadb_sta(mac);
			if (!sta)
				continue;

			map_fill_non_assoc_sta_stats(sta, wdev_id, radio->opclass);
			map_stadb_stah_unref((stah_t *)sta);
		}
	}
	blobmsg_close_array(&b, stas_stats_array);

	return ubus_send_reply(ctx, req, b.head);
}

static const struct ubus_method map_stats_methods[] = {
	UBUS_METHOD(MAP_METHOD_SET_PERIODS_NAME, map_set_periods, map_set_periods_policy),
	UBUS_METHOD(MAP_METHOD_GET_MONITOR_STATS_NAME, map_get_monitor_stats, map_get_monitor_stats_policy),
};

static struct ubus_object_type map_stats_obj_type =
	UBUS_OBJECT_TYPE(MAP_STATISTICS_OBJ_NAME, map_stats_methods);

static struct ubus_object map_stats_obj = {
	.name = MAP_STATISTICS_OBJ_NAME,
	.type = &map_stats_obj_type,
	.methods = map_stats_methods,
	.n_methods = ARRAY_SIZE(map_stats_methods),
};

static int map_notify_sta_connected(uint8_t *dev_mac, uint8_t *mac)
{
	sta_table_t *sta = map_get_stadb_sta(mac);
	if (!sta) {
		MAP_ERROR("Find sta " MAP_MACFMT " failed: not exist in table\n",
			MAP_MACARG(mac));
		return -1;
	}

	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, dev_mac);

	map_fill_station(sta, MAP_ATTR_STATION_NAME);

	map_stadb_stah_unref((stah_t *)sta);

	return 0;
}

static void map_notify_sta_disconnected(uint8_t *dev_mac, uint8_t *mac)
{
	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, dev_mac);
	map_blobmsg_add_mac(MAP_ATTR_STA_MAC_NAME, mac);
}

static void map_notify_bss_connected(uint8_t *dev_id,
	uint8_t *peer_mac, uint8_t result)
{
	map_fill_wdev_associated(dev_id, peer_mac, result);
}

static void map_notify_frame_received(uint8_t *dev_id,
	uint8_t *frame, uint16_t frame_len, uint8_t *rssi_adv)
{
	map_fill_frame_received(dev_id, frame, frame_len);
	map_fill_rssi_adv(rssi_adv);
}

static int map_notify_radio_updated(uint8_t *mac, int only_basic)
{
	radio_table_t *radio = map_get_stadb_radio(mac);

	if (!radio)
		return -1;

	map_fill_wiphy(radio, only_basic);

	return 0;
}

static int map_notify_bss_updated(uint8_t *mac, uint8_t *state)
{
	bss_table_t *bss = map_get_stadb_bss(mac);

	if (!bss)
		return -1;

	map_fill_wdev(bss, state);
	map_stadb_stah_unref((stah_t *)bss);

	return 0;
}

static void map_notify_bss_deleted(uint8_t *mac)
{
	map_blobmsg_add_mac(MAP_ATTR_WDEV_ID_NAME, mac);
}

static int map_notify_wdev_stats_updated_event(uint8_t *mac)
{
	bss_table_t *bss = NULL;

	bss = map_get_stadb_bss(mac);

	if (!bss)
		return -1;

	map_fill_wdev_stats_updated(bss);
	map_stadb_stah_unref((stah_t *)bss);

	return 0;
}

static int map_notify_stas_stats_updated_event(uint8_t *wdev_id)
{
	bss_table_t *bss = map_get_stadb_bss(wdev_id);

	if (!bss)
		return -1;

	map_stadb_stah_unref((stah_t *)bss);

	map_fill_stas_stats_updated(wdev_id);

	return 0;
}

static int map_notify_mon_stats_updated_event(uint8_t *wdev_id)
{
	uint8_t opclass, iftype;
	bss_table_t *bss = map_get_stadb_bss(wdev_id);

	if (!bss)
		return -1;

	opclass = bss->operation_class;
	iftype = bss->iftype;
	map_stadb_stah_unref((stah_t *)bss);

	if (iftype != NODE_TYPE_VAP)
		return -1;

	map_fill_mon_stats_updated(wdev_id, opclass);

	return 0;
}

void map_notify_event(map_event_t *event)
{
	const char *evt = NULL;
	struct ubus_object *obj = NULL;

	blob_buf_init(&b, 0);

	MAP_DEBUG("Notify event %u\n", event->id);

	switch (event->id) {
	case MAP_EVENT_STA_CONNECTED:
		evt = MAP_EVENT_STA_CONNECTED_NAME;
		if (!map_notify_sta_connected(event->dev_id,
			event->u.sta))
			obj = &map_mlme_obj;
		break;
	case MAP_EVENT_STA_DISCONNECTED:
		evt = MAP_EVENT_STA_DISCONNECTED_NAME;
		map_notify_sta_disconnected(event->dev_id,
			event->u.sta);
		obj = &map_mlme_obj;
		break;
	case MAP_EVENT_WDEV_ASSOCIATED:
		evt = MAP_EVENT_WDEV_ASSOCIATED_NAME;
		map_notify_bss_connected(event->dev_id,
			event->u.sta, event->roam_result);
		obj = &map_mlme_obj;
		break;
	case MAP_EVENT_FRAME_RECEIVED:
		evt = MAP_EVENT_FRAME_RECEIVED_NAME;
		map_notify_frame_received(event->dev_id,
			event->frame, event->frame_len, event->rssi_adv);
		obj = &map_mlme_obj;
		if (event->frame)
			MAP_FREE(event->frame);
		break;
	case MAP_EVENT_WIPHY_UPDATED:
		evt = MAP_EVENT_WIPHY_UPDATED_NAME;
		if (!map_notify_radio_updated(event->u.radio, 0))
			obj = &map_intf_obj;
		break;
	case MAP_EVENT_WDEV_UPDATED:
		evt = MAP_EVENT_WDEV_UPDATED_NAME;
		if (!map_notify_bss_updated(event->dev_id, NULL))
			obj = &map_intf_obj;
		break;
	case MAP_EVENT_WDEV_STATE_UPDATED:
		evt = MAP_EVENT_WDEV_UPDATED_NAME;
		if (!map_notify_bss_updated(event->dev_id, &event->state))
			obj = &map_intf_obj;
		break;
	case MAP_EVENT_WDEV_DELETED:
		evt = MAP_EVENT_WDEV_DELETED_NAME;
		map_notify_bss_deleted(event->dev_id);
		obj = &map_intf_obj;
		break;
	case MAP_EVENT_WDEV_STATS_UPDATED:
		evt = MAP_EVENT_WDEV_STATS_UPDATED_NAME;
		if (!map_notify_wdev_stats_updated_event(event->dev_id))
			obj = &map_stats_obj;
		break;
	case MAP_EVENT_STA_STATS_UPDATED:
		evt = MAP_EVENT_STA_STATS_UPDATED_NAME;
		if (!map_notify_stas_stats_updated_event(event->dev_id))
			obj = &map_stats_obj;
		break;
	case MAP_EVENT_MON_STATS_UPDATED:
		evt = MAP_EVENT_MONITOR_STATS_UPDATED_NAME;
		if (!map_notify_mon_stats_updated_event(event->dev_id))
			obj = &map_stats_obj;
		break;
	default:
		break;
	}

	if (evt && obj) {
		MAP_DEBUG("ubus_notify: Notify %s event %s\n", obj->name, evt);
		ubus_notify(g_ctx.ubus_ctx, obj, evt, b.head, -1);
	}

	/* report the radio basic info */
	if (MAP_EVENT_WDEV_UPDATED == event->id) {
		if (map_get_stadb_radio(event->dev_id)) {
			blob_buf_init(&b, 0);
			evt = MAP_EVENT_WIPHY_UPDATED_NAME;
			if (obj && !map_notify_radio_updated(event->dev_id, 1)) {
				MAP_DEBUG("Notify %s event %s\n", obj->name, evt);
				ubus_notify(g_ctx.ubus_ctx, obj, evt, b.head, -1);
			}
		}
	}
}

static int map_add_objects(void)
{
	int ret;

	MAP_DEBUG("Add map ubus %s object\n", map_intf_obj.name);
	ret = ubus_add_object(g_ctx.ubus_ctx, &map_intf_obj);
	if (ret) {
		MAP_ERROR("Failed to add ubus %s object: %s\n",
			map_intf_obj.name, ubus_strerror(ret));
		return -1;
	}

	MAP_DEBUG("Add map ubus %s object\n", map_mlme_obj.name);
	ret = ubus_add_object(g_ctx.ubus_ctx, &map_mlme_obj);
	if (ret) {
		MAP_ERROR("Failed to add ubus %s object: %s\n",
			map_mlme_obj.name, ubus_strerror(ret));
		return -1;
	}

	MAP_DEBUG("Add map ubus %s object\n", map_stats_obj.name);
	ret = ubus_add_object(g_ctx.ubus_ctx, &map_stats_obj);
	if (ret) {
		MAP_ERROR("Failed to add ubus %s object: %s\n",
			map_stats_obj.name, ubus_strerror(ret));
		return -1;
	}

	return 0;
}

int map_service_init(void)
{
	MAP_DEBUG("Connect map to ubus and add map ubus objects\n");

	if (!(g_ctx.ubus_ctx = ubus_connect(NULL))) {
		MAP_ERROR("Failed to connect ubus\n");
		return -1;
	}

	ubus_add_uloop(g_ctx.ubus_ctx);

	if (map_extcfg_init() < 0)
		MAP_WARN("Failed to init external config\n");

	if (map_ctrl_init() < 0)
		MAP_WARN("Failed to init ctrl\n");

	blob_buf_init(&b, 0);

	return map_add_objects();
}

void map_service_deinit(void)
{
	MAP_DEBUG("Disconnect map from ubus\n");

	blob_buf_free(&b);
	map_extcfg_deinit();
	map_ctrl_deinit();
	if (g_ctx.ubus_ctx)
		ubus_free(g_ctx.ubus_ctx);
}

