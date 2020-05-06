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
#include "map_api.h"
#include "map_dbg.h"
#include "map_extcfg.h"
#include "map_ctrl.h"
#include "map_server.h"

static struct blob_buf b;

int map_extcfg_init(void)
{
	uint32_t id = 0;

	if (ubus_lookup_id(g_ctx.ubus_ctx, MAP_EXTCFG_OBJ_NAME, &id)) {
		MAP_WARN("Extcfg %s does not loaded\n", MAP_EXTCFG_OBJ_NAME);
		return -1;
	}

	g_ctx.extcfg_objid = id;

	blob_buf_init(&b, 0);

	return 0;
}

void map_extcfg_deinit(void)
{
	blob_buf_free(&b);
}

static inline int map_extcfg_invoke_with_result(const char *method, ubus_data_handler_t cb, void *ctx)
{
	MAP_DEBUG("Call external config: %s\n", method);
	return ubus_invoke(g_ctx.ubus_ctx, g_ctx.extcfg_objid, method, b.head, cb, ctx, 0);
}
#define map_extcfg_invoke(_m)		map_extcfg_invoke_with_result(_m, NULL, NULL)

static void map_extcfg_cfg_wiphy_attrs(struct blob_attr **info)
{
	if (info[MAP_WIPHY_ATTR_TEAR_DOWN]) {
		blobmsg_add_u32(&b, MAP_EXTCFG_WIPHY_ATTR_TEARDOWN_NAME,
			blobmsg_get_u32(info[MAP_WIPHY_ATTR_TEAR_DOWN]));
		if (blobmsg_get_u32(info[MAP_WIPHY_ATTR_TEAR_DOWN]) == 1)
			map_del_all_intf_config();
	}
}

int map_extcfg_cfg_wiphy(const char *wiphy_name, struct blob_attr **info)
{
	if (!wiphy_name || !info)
		return -1;

	if (!info[MAP_WIPHY_ATTR_TEAR_DOWN])
		return 0;

	if (blobmsg_get_u32(info[MAP_WIPHY_ATTR_TEAR_DOWN]) == 0)
		return 0;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, MAP_EXTCFG_WIPHY_ATTR_WIPHY_NAME, wiphy_name);
	map_extcfg_cfg_wiphy_attrs(info);

	return map_extcfg_invoke(MAP_EXTCFG_METHOD_CFG_WIPHY);
}

static void map_extcfg_add_wdev_attrs(struct blob_attr **info)
{
	if (info[MAP_WDEV_ATTR_SSID])
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_SSID_NAME,
			blobmsg_data(info[MAP_WDEV_ATTR_SSID]),
			blobmsg_len(info[MAP_WDEV_ATTR_SSID]));

	if (info[MAP_WDEV_ATTR_AUTH])
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_AUTH_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_AUTH]));

	if (info[MAP_WDEV_ATTR_ENCRYP])
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_ENCRYP_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_ENCRYP]));

	if (info[MAP_WDEV_ATTR_KEY])
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_KEY_NAME,
			blobmsg_data(info[MAP_WDEV_ATTR_KEY]),
			blobmsg_len(info[MAP_WDEV_ATTR_KEY]));

	if (info[MAP_WDEV_ATTR_WPS])
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_WPS_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_WPS]));

	if (info[MAP_WDEV_ATTR_DISABLE])
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_DISABLE_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_DISABLE]));

	if (info[MAP_WDEV_ATTR_4ADDR])
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_4ADDR_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_4ADDR]));

	if (info[MAP_WDEV_ATTR_HIDE])
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_HIDE_SSID_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_HIDE]));

#ifdef SPARTAN_PLATFORM
	if (info[MAP_WDEV_ATTR_MAP_MTYPES]) {
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_MAP_TYPES_NAME,
			blobmsg_get_u32(info[MAP_WDEV_ATTR_MAP_MTYPES]));
	}
#endif
}

static void map_extcfg_add_wdev_backhaul_table(struct blob_attr **info)
{
	void *backhaul_tbl = blobmsg_open_table(&b, MAP_EXTCFG_ATTR_BACKHAUL_NAME);

	if (info[MAP_BACKHAUL_ATTR_SSID])
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_BACKHAUL_ATTR_SSID_NAME,
			blobmsg_data(info[MAP_BACKHAUL_ATTR_SSID]),
			blobmsg_len(info[MAP_BACKHAUL_ATTR_SSID]));

	if (info[MAP_BACKHAUL_ATTR_AUTH])
		blobmsg_add_u32(&b, MAP_EXTCFG_BACKHAUL_ATTR_AUTH_NAME,
			blobmsg_get_u32(info[MAP_BACKHAUL_ATTR_AUTH]));

	if (info[MAP_BACKHAUL_ATTR_ENCRYP])
		blobmsg_add_u32(&b, MAP_EXTCFG_BACKHAUL_ATTR_ENCRYP_NAME,
			blobmsg_get_u32(info[MAP_BACKHAUL_ATTR_ENCRYP]));

	if (info[MAP_BACKHAUL_ATTR_KEY])
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_BACKHAUL_ATTR_KEY_NAME,
			blobmsg_data(info[MAP_BACKHAUL_ATTR_KEY]),
			blobmsg_len(info[MAP_BACKHAUL_ATTR_KEY]));

	blobmsg_close_table(&b, backhaul_tbl);
}

static const struct blobmsg_policy extcfg_policy[NUM_MAP_EXTCFG_ATTRS] = {
	[MAP_EXTCFG_ATTR_WDEV] = { .name = MAP_EXTCFG_ATTR_WDEV_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_ATTR_SSID] = { .name = MAP_EXTCFG_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_EXTCFG_ATTR_AUTH] = { .name = MAP_EXTCFG_ATTR_AUTH_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_ENCRYP] = { .name = MAP_EXTCFG_ATTR_ENCRYP_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_KEY] = { .name = MAP_EXTCFG_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_EXTCFG_ATTR_MAP_TYPES] = { .name = MAP_EXTCFG_ATTR_MAP_TYPES_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy extcfg_devdata_policy[NUM_MAP_EXTCFG_DEVDATA_ATTRS] = {
	[MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME] = { .name = MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME] = { .name = MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME] = { .name = MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER] = { .name = MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER] = { .name = MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER_NAME, .type = BLOBMSG_TYPE_STRING},
};

static void map_extcfg_add_wdev_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *ifname = (char *)req->priv;
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];

	if (!ifname)
		return;

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS, tb, blob_data(msg), blob_len(msg));

	ifname[0] = '\0';
	if (tb[MAP_EXTCFG_ATTR_WDEV])
		strncpy(ifname, blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WDEV]), IFNAMSIZ - 1);
}

int map_extcfg_add_wdev(const char *wiphy_name, struct blob_attr **info, char *ifname)
{
	if (g_ctx.extcfg_objid <= 0)
		return -1;

	if (!wiphy_name || !info)
		return -1;

	if (!info[MAP_WDEV_ATTR_MODE]) {
		MAP_WARN("Fail external config: miss wdev mode\n");
		return -1;
	}

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, MAP_EXTCFG_ATTR_WIPHY_NAME, wiphy_name);
	blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_MODE_NAME,
		blobmsg_get_u32(info[MAP_WDEV_ATTR_MODE]));

	map_extcfg_add_wdev_attrs(info);

	return map_extcfg_invoke_with_result(MAP_EXTCFG_METHOD_ADD_WDEV, map_extcfg_add_wdev_cb, ifname);
}

int map_extcfg_del_wdev(const char *wdev_name)
{
	if (g_ctx.extcfg_objid <= 0)
		return -1;

	if (!wdev_name)
		return -1;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, MAP_EXTCFG_ATTR_WDEV_NAME, wdev_name);

	return map_extcfg_invoke(MAP_EXTCFG_METHOD_DEL_WDEV);
}

int map_extcfg_cfg_wdev(const char *wdev_name, struct blob_attr **info,
	int is_configured, struct blob_attr **backhaul_info)
{
	if (g_ctx.extcfg_objid <= 0)
		return -1;

	if (!wdev_name || !info)
		return -1;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, MAP_EXTCFG_ATTR_WDEV_NAME, wdev_name);

	map_extcfg_add_wdev_attrs(info);

	if (is_configured)
		map_extcfg_add_wdev_backhaul_table(backhaul_info);

	return map_extcfg_invoke(MAP_EXTCFG_METHOD_CFG_WDEV);
}

int map_extcfg_start_wps(const char *wdev_name)
{
	if (g_ctx.extcfg_objid <= 0)
		return -1;

	if (!wdev_name)
		return -1;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, MAP_EXTCFG_ATTR_WDEV_NAME, wdev_name);

	return map_extcfg_invoke(MAP_EXTCFG_METHOD_START_WPS);
}

static void map_extcfg_get_bsscfg_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	map_bsscfg_t *bss_cfg = (map_bsscfg_t *)req->priv;
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];

	if (!bss_cfg)
		return;

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS, tb, blob_data(msg), blob_len(msg));

	if (tb[MAP_EXTCFG_ATTR_AUTH])
		bss_cfg->auth_mode = blobmsg_get_u32(tb[MAP_EXTCFG_ATTR_AUTH]);

	if (tb[MAP_EXTCFG_ATTR_ENCRYP])
		bss_cfg->encrypt = blobmsg_get_u32(tb[MAP_EXTCFG_ATTR_ENCRYP]);

	if (tb[MAP_EXTCFG_ATTR_SSID]) {
		bss_cfg->ssid = blobmsg_data(tb[MAP_EXTCFG_ATTR_SSID]);
		bss_cfg->ssid_len = blobmsg_data_len(tb[MAP_EXTCFG_ATTR_SSID]);
	}

	if (tb[MAP_EXTCFG_ATTR_KEY]) {
		bss_cfg->key = blobmsg_data(tb[MAP_EXTCFG_ATTR_KEY]);
		bss_cfg->key_len = blobmsg_data_len(tb[MAP_EXTCFG_ATTR_KEY]);
	}

	if (tb[MAP_EXTCFG_ATTR_MAP_TYPES])
		bss_cfg->mtypes = blobmsg_get_u32(tb[MAP_EXTCFG_ATTR_MAP_TYPES]);
	else
		bss_cfg->mtypes = MAP_BSSCFG_MTYPES_INVALID;
}

int map_extcfg_get_bsscfg(const char *wdev_name, map_bsscfg_t *bss_cfg)
{
	if (g_ctx.extcfg_objid <= 0)
		return -1;

	if (!wdev_name)
		return -1;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, MAP_EXTCFG_ATTR_WDEV_NAME, wdev_name);

	return map_extcfg_invoke_with_result(MAP_EXTCFG_METHOD_GET_BSSCFG, map_extcfg_get_bsscfg_cb, bss_cfg);
}

static void map_extcfg_get_devdata_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	map_devdata_t *dev_data = (map_devdata_t *)req->priv;
	struct blob_attr *tb[NUM_MAP_EXTCFG_DEVDATA_ATTRS];

	if (!dev_data)
		return;

	blobmsg_parse(extcfg_devdata_policy, NUM_MAP_EXTCFG_DEVDATA_ATTRS, tb, blob_data(msg), blob_len(msg));

	if (tb[MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME])
		dev_data->device_name = blobmsg_get_string(tb[MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME]);

	if (tb[MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME])
		dev_data->manufacturer_name = blobmsg_get_string(tb[MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME]);

	if (tb[MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME])
		dev_data->model_name = blobmsg_get_string(tb[MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME]);

	if (tb[MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER])
		dev_data->model_number = blobmsg_get_string(tb[MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER]);

	if (tb[MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER])
		dev_data->serial_number = blobmsg_get_string(tb[MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER]);
}

int map_extcfg_get_devdata(map_devdata_t *dev_data)
{
	if (g_ctx.extcfg_objid <= 0)
		return -1;

	blob_buf_init(&b, 0);

	return map_extcfg_invoke_with_result(MAP_EXTCFG_METHOD_GET_DEVDATA, map_extcfg_get_devdata_cb, dev_data);
}
