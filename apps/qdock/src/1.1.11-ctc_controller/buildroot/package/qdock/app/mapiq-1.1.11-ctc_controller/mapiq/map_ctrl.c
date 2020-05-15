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
#include "map_server.h"
#include "map_ctrl.h"

static struct blob_buf b;

static const char *g_map_ctrl_rc_names[] = {
	[MAP_CTRL_RC_OK] = "Success",
	[MAP_CTRL_RC_INVALID_VALUE] = "Invalid Value",
	[MAP_CTRL_RC_MISS_ARGUMENT] = "Miss Argument",
	[MAP_CTRL_RC_NOT_SUPPORTED] = "Not Supported",
	[MAP_CTRL_RC_UNKNOWN_ERROR] = "Unknown Error",
};

static int map_ctrl_response(struct ubus_context *ctx,
	struct ubus_request_data *req, const char *method, uint32_t rc)
{
	if (rc >= ARRAY_SIZE(g_map_ctrl_rc_names))
		rc = MAP_CTRL_RC_UNKNOWN_ERROR;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, MAP_CTRL_ATTR_RC_NAME, g_map_ctrl_rc_names[rc]);
	return ubus_send_reply(ctx, req, b.head);
}

static const char *g_map_ctrl_help_string = "ubus call " MAP_CTRL_OBJ_NAME " <method> [<json>]";
static int map_ctrl_help(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	void *methods;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, MAP_CTRL_ATTR_FORMAT_NAME, g_map_ctrl_help_string);

	methods = blobmsg_open_array(&b, MAP_CTRL_ATTR_METHODS_NAME);
	blobmsg_add_string(&b, NULL, MAP_CTRL_METHOD_HELP_NAME);
	blobmsg_add_string(&b, NULL, MAP_CTRL_METHOD_GET_VERSION_NAME);
	blobmsg_add_string(&b, NULL, MAP_CTRL_METHOD_SET_CONFIG_NAME);
	blobmsg_add_string(&b, NULL, MAP_CTRL_METHOD_GET_CONFIG_NAME);
	blobmsg_add_string(&b, NULL, MAP_CTRL_METHOD_TEST_NAME);
	blobmsg_close_array(&b, methods);

	return ubus_send_reply(ctx, req, b.head);
}

static int map_ctrl_get_version(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	char version[64];

	snprintf(version, 64, "%s-%s", MAPIQ_VERSION, MAPIQ_SUBVERSION);
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, MAP_CTRL_ATTR_VERSION_NAME, (const char *)version);
	return ubus_send_reply(ctx, req, b.head);
}

enum {
	MAP_CTRL_CONFIGS = 0,

	__MAP_CTRL_CONFIGS_MAX
};

static const struct blobmsg_policy map_ctrl_configs_policy[] = {
	[MAP_CTRL_CONFIGS] = { .name = MAP_CTRL_ATTR_CONFIGS_NAME, .type = BLOBMSG_TYPE_TABLE },
};

static map_ctrl_conf_t g_map_config_validity[NUM_MAP_CTRL_CONF_ATTRS] = {
	[MAP_CTRL_CONF_ATTR_XXX] = { 0, 3600, NULL },
};

static const struct blobmsg_policy map_ctrl_conf_policy[NUM_MAP_CTRL_CONF_ATTRS] = {
	MAP_ATTRS_POLICY_INIT(MAP_CTRL_CONF_ATTR_XXX, BLOBMSG_TYPE_INT32),
};

enum {
	MAP_CTRL_TEST_SUBCMD = 0,
	MAP_CTRL_TEST_PARAMS,

	__MAP_CTRL_TEST_MAX
};

static const struct blobmsg_policy map_ctrl_test_policy[] = {
	[MAP_CTRL_TEST_SUBCMD] = { .name = MAP_CTRL_ATTR_TEST_SUBCMD_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_TEST_PARAMS] = { .name = MAP_CTRL_ATTR_TEST_PARAMS_NAME, .type = BLOBMSG_TYPE_TABLE },
};

static const struct blobmsg_policy map_ctrl_testparam_policy[NUM_MAP_CTRL_TESTPARAM_ATTRS] = {
	MAP_ATTRS_POLICY_INIT(MAP_CTRL_TESTPARAM_ATTR_WDEV_ID, BLOBMSG_TYPE_STRING),
	MAP_ATTRS_POLICY_INIT(MAP_CTRL_TESTPARAM_ATTR_FRONTHAUL_BSS, BLOBMSG_TYPE_INT32),
	MAP_ATTRS_POLICY_INIT(MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_BSS, BLOBMSG_TYPE_INT32),
	MAP_ATTRS_POLICY_INIT(MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_STA, BLOBMSG_TYPE_INT32),
};

static void map_ctrl_reset_configs(void)
{
	/* TODO: reset the configuation */
}

static int map_ctrl_check_config(uint32_t attrid, struct blob_attr *attr)
{
	int val = 0;

	if (attrid >= ARRAY_SIZE(g_map_config_validity))
		return -1;
	if (g_map_config_validity[attrid].valid)
		return g_map_config_validity[attrid].valid(attr);

	if (map_ctrl_conf_policy[attrid].type != BLOBMSG_TYPE_INT32
		&& map_ctrl_conf_policy[attrid].type != BLOBMSG_TYPE_INT16
		&& map_ctrl_conf_policy[attrid].type != BLOBMSG_TYPE_INT8)
		return 0;

	if (map_ctrl_conf_policy[attrid].type == BLOBMSG_TYPE_INT32)
		val = (int32_t)blobmsg_get_u32(attr);
	else if (map_ctrl_conf_policy[attrid].type == BLOBMSG_TYPE_INT16)
		val = (int16_t)blobmsg_get_u16(attr);
	else if (map_ctrl_conf_policy[attrid].type == BLOBMSG_TYPE_INT8)
		val = (int8_t)blobmsg_get_u8(attr);

	if (val > g_map_config_validity[attrid].max
		|| val < g_map_config_validity[attrid].min)
		return -1;
	return 0;
}

#define MAP_CTRL_CHECK_CONFIG(_attrid)	((infos[_attrid]) \
					&& (map_ctrl_check_config(_attrid, infos[_attrid]) >= 0))
static int map_ctrl_set_configs_from_attrs(struct blob_attr **infos)
{
	/* TODO: set the configuation */
	if (MAP_CTRL_CHECK_CONFIG(MAP_CTRL_CONF_ATTR_XXX))
		;

	return 0;
}

static int map_ctrl_set_configs(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_CTRL_CONFIGS_MAX];

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_ctrl_configs_policy, __MAP_CTRL_CONFIGS_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (!tb[MAP_CTRL_CONFIGS]) {
		map_ctrl_reset_configs();
	} else {
		struct blob_attr *conf_tb[NUM_MAP_CTRL_CONF_ATTRS];
		blobmsg_parse(map_ctrl_conf_policy, NUM_MAP_CTRL_CONF_ATTRS, conf_tb,
			blobmsg_data(tb[MAP_CTRL_CONFIGS]), blobmsg_len(tb[MAP_CTRL_CONFIGS]));
		if (map_ctrl_set_configs_from_attrs(conf_tb) < 0)
			return map_ctrl_response(ctx, req, method, MAP_CTRL_RC_INVALID_VALUE);
	}

	return map_ctrl_response(ctx, req, method, MAP_CTRL_RC_OK);
}

static int map_ctrl_send_configs(struct ubus_context *ctx,
	struct ubus_request_data *req, struct blob_attr **infos)
{
	blob_buf_init(&b, 0);

	if (!infos) {
		/* TODO: send all configs back */

		return 0;
	}

	/* TODO: send the specified configuation back */
	if (infos[MAP_CTRL_CONF_ATTR_XXX])
		;

	return ubus_send_reply(ctx, req, b.head);
}

static int map_ctrl_get_configs(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_CTRL_CONFIGS_MAX];
	struct blob_attr *conf_tb[NUM_MAP_CTRL_CONF_ATTRS];
	struct blob_attr **p_conf_tb = NULL;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_ctrl_configs_policy, __MAP_CTRL_CONFIGS_MAX,
		tb, blob_data(msg), blob_len(msg));

	if (tb[MAP_CTRL_CONFIGS]) {
		blobmsg_parse(map_ctrl_conf_policy, NUM_MAP_CTRL_CONF_ATTRS, conf_tb,
			blobmsg_data(tb[MAP_CTRL_CONFIGS]), blobmsg_len(tb[MAP_CTRL_CONFIGS]));
		p_conf_tb = conf_tb;
	}

	return map_ctrl_send_configs(ctx, req, p_conf_tb);
}


static void map_apply_intf_config(struct map_intf_cfg *intf)
{
	int is_fh = 0, is_bh = 0;
	bss_table_t *bss = map_get_local_bss_by_ssid(intf->ssid);

	if (!bss)
		return;

	if (bss->flag & BSS_FLAG_DOWN)
		goto _out;

	if (intf->map_iftype & MAP_INTF_fBSS)
		is_fh = 1;

	if (intf->map_iftype & MAP_INTF_bBSS)
		is_bh = 1;

	map_conf_bss_maptype(bss, is_fh, is_bh);

_out:
	map_stadb_stah_unref(bss);
}

static void map_update_intf_config(struct map_intf_cfg *intf,
	int is_fh, int is_bh, int is_reset)
{
	if (is_reset)
		intf->map_iftype = 0;
	if (is_fh)
		intf->map_iftype |= MAP_INTF_fBSS;
	if (is_bh)
		intf->map_iftype |= MAP_INTF_bBSS;
}

static void map_add_and_update_intf_config(char *ssid,
	int is_fh, int is_bh, int is_reset)
{
	struct map_intf_cfg *intf;

	if (!strlen(ssid))
		return;

	pthread_mutex_lock(&g_cfg.ifcfg_mutex);
	list_for_each_entry(intf, &g_cfg.ifcfg_head, lh) {
		if (!strcmp(intf->ssid, ssid)) {
			map_update_intf_config(intf, is_fh, is_bh, is_reset);
			pthread_mutex_unlock(&g_cfg.ifcfg_mutex);
			return;
		}
	}
	pthread_mutex_unlock(&g_cfg.ifcfg_mutex);

	intf = MAP_CALLOC(1, sizeof(struct map_intf_cfg));
	if (NULL == intf)
		return;

	strncpy(intf->ssid, ssid, IEEE80211_SSID_MAXLEN);
	map_update_intf_config(intf, is_fh, is_bh, is_reset);
	pthread_mutex_lock(&g_cfg.ifcfg_mutex);
	list_add_tail(&intf->lh, &g_cfg.ifcfg_head);
	pthread_mutex_unlock(&g_cfg.ifcfg_mutex);
}

static map_intf_cfg_t *map_find_intf_config(char *ssid)
{
	struct map_intf_cfg *intf;

	pthread_mutex_lock(&g_cfg.ifcfg_mutex);
	list_for_each_entry(intf, &g_cfg.ifcfg_head, lh) {
		if (!strcmp(intf->ssid, ssid)) {
			pthread_mutex_unlock(&g_cfg.ifcfg_mutex);
			return intf;
		}
	}
	pthread_mutex_unlock(&g_cfg.ifcfg_mutex);

	return NULL;
}

void map_del_intf_config(char *ssid)
{
	struct map_intf_cfg *intf;

	intf = map_find_intf_config(ssid);

	if (!intf) {
		MAP_INFO("cannot find the corresponding intf with ssid %s\n",
			ssid);
		return;
	}

	pthread_mutex_lock(&g_cfg.ifcfg_mutex);
	list_del(&intf->lh);
	MAP_FREE(intf);
	pthread_mutex_unlock(&g_cfg.ifcfg_mutex);
}

void map_del_all_intf_config()
{
	struct map_intf_cfg *intf;

	pthread_mutex_lock(&g_cfg.ifcfg_mutex);
	while (!list_empty(&g_cfg.ifcfg_head)) {
		intf = list_first_entry(&g_cfg.ifcfg_head, struct map_intf_cfg, lh);
		list_del(&intf->lh);
		MAP_FREE(intf);
	}
	pthread_mutex_unlock(&g_cfg.ifcfg_mutex);
}

void map_load_intf_config(const char *in_str, int is_fh, int is_bh)
{
	char *p;
	char *str, *str_p;

	if(NULL == in_str
		|| 0 == strlen(in_str))
		return;

	str = MAP_MALLOC(strlen(in_str) + 1);
	if(NULL == str)
		return;

	str_p = str;
	strcpy(str, in_str);

	do {
		p = strchr(str, ',');
		if(p) {
			*p = '\0';
			p++;
			while(isspace(*p)) ++p;
		}

		map_add_and_update_intf_config(str, is_fh, is_bh, 0);

		str = p;
	} while(NULL != str && 0 != strlen(str));

	MAP_FREE(str_p);
}

void map_config_bss_mtype(char *ssid, uint8_t mtype)
{
	int is_fh = 0, is_bh = 0;

	if (mtype & MAP_MTYPE_FRONTHAUL_BSS)
		is_fh = 1;

	if (mtype & MAP_MTYPE_BACKHAUL_BSS)
		is_bh = 1;

	map_add_and_update_intf_config(ssid, is_fh, is_bh, 0);
}

void map_init_wdev(uint8_t *dev_mac)
{
	struct map_intf_cfg *intf;
	bss_table_t *bss;
	static uint8_t bsta = 0, start_monitoring = 0;

	bss = map_get_stadb_bss(dev_mac);
	if (!bss) {
		MAP_ERROR("bss of "MAP_MACFMT" is not in table list\n",
			MAP_MACARG(dev_mac));
		return;
	}

	if (bss->iftype == NODE_TYPE_STA) {
		/* assumed the created sta interface had been backhaul sta */
		if (!bsta) {
			map_conf_backhaul_sta(bss, 1);
			bsta = 1;
		}
	}
	else if (bss->iftype == NODE_TYPE_VAP) {
		intf = map_find_intf_config(bss->ssid);
		if (intf)
			map_apply_intf_config(intf);

		if (!start_monitoring && bss->radio
			&& MAP_MAC_EQ(bss->h.mac, bss->radio->h.mac))
			map_start_chan_monitoring(dev_mac);
	}

	map_stadb_stah_unref((stah_t *)bss);
}

static uint32_t map_ctrl_test_set_wdev_map_iftype(struct blob_attr **infos)
{
	bss_table_t *bss;
	struct ether_addr addr;
	int bsta = 0, fbss = 0, bbss = 0;
	uint32_t rc = MAP_CTRL_RC_OK;

	if (!infos || !infos[MAP_CTRL_TESTPARAM_ATTR_WDEV_ID]) {
		MAP_ERROR("Set wdev map iftype failed: missing wdev id\n");
		return MAP_CTRL_RC_MISS_ARGUMENT;
	}

	if (ether_aton_r(blobmsg_get_string(
		infos[MAP_CTRL_TESTPARAM_ATTR_WDEV_ID]), &addr) == NULL) {
		MAP_ERROR("Set wdev map iftype failed: wdev id should mac address\n");
		return MAP_CTRL_RC_INVALID_VALUE;
	}

	if (infos[MAP_CTRL_TESTPARAM_ATTR_FRONTHAUL_BSS])
		fbss = blobmsg_get_u32(infos[MAP_CTRL_TESTPARAM_ATTR_FRONTHAUL_BSS]);
	if (infos[MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_BSS])
		bbss = blobmsg_get_u32(infos[MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_BSS]);
	if (infos[MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_STA])
		bsta = blobmsg_get_u32(infos[MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_STA]);

	bss = map_get_stadb_bss(addr.ether_addr_octet);
	if (!bss) {
		MAP_ERROR("Set wdev map iftype failed: not find wdev\n");
		return MAP_CTRL_RC_INVALID_VALUE;
	}

	if (bss->iftype == NODE_TYPE_VAP)
		map_conf_bss_maptype(bss, fbss, bbss);
	else if (bss->iftype == NODE_TYPE_STA)
		map_conf_backhaul_sta(bss, bsta);
	else {
		MAP_ERROR("Set wdev map iftype failed: wdev type is %u\n", bss->iftype);
		rc = MAP_CTRL_RC_NOT_SUPPORTED;
	}

	map_stadb_stah_unref((stah_t *)bss);

	return rc;
}

#define MAP_CTRL_TEST_SUBCMD(_a)	{ #_a, map_ctrl_test_##_a }
static map_ctrl_test_t g_map_test_subcmd[] = {
	MAP_CTRL_TEST_SUBCMD(set_wdev_map_iftype),
};

static uint32_t map_ctrl_test_process(const char *subcmd, struct blob_attr **infos)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(g_map_test_subcmd); i++) {
		if (0 == strcmp(g_map_test_subcmd[i].subcmd, subcmd)) {
			if (g_map_test_subcmd[i].process_subcmd_cb)
				return g_map_test_subcmd[i].process_subcmd_cb(infos);
			return 0;
		}
	}

	MAP_ERROR("Test command failed: not support %s\n", subcmd);
	return MAP_CTRL_RC_NOT_SUPPORTED;
}

static int map_ctrl_test(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MAP_CTRL_TEST_MAX];
	struct blob_attr *param_tb[NUM_MAP_CTRL_TESTPARAM_ATTRS];
	struct blob_attr **p_param_tb = NULL;
	uint32_t rc;

	MAP_DEBUG("Method %s called by peer %u\n", method, req->peer);

	blobmsg_parse(map_ctrl_test_policy, __MAP_CTRL_TEST_MAX,
		tb, blob_data(msg), blob_len(msg));
	if (!tb[MAP_CTRL_TEST_SUBCMD])
		return map_ctrl_response(ctx, req, method, MAP_CTRL_RC_MISS_ARGUMENT);

	if (tb[MAP_CTRL_TEST_PARAMS]) {
		blobmsg_parse(map_ctrl_testparam_policy, NUM_MAP_CTRL_TESTPARAM_ATTRS, param_tb,
			blobmsg_data(tb[MAP_CTRL_TEST_PARAMS]), blobmsg_len(tb[MAP_CTRL_TEST_PARAMS]));
		p_param_tb = param_tb;
	}

	rc = map_ctrl_test_process((const char *)
		blobmsg_get_string(tb[MAP_CTRL_TEST_SUBCMD]), p_param_tb);

	return map_ctrl_response(ctx, req, method, rc);
}

static const struct ubus_method map_ctrl_methods[] = {
	UBUS_METHOD_NOARG(MAP_CTRL_METHOD_HELP_NAME, map_ctrl_help),
	UBUS_METHOD_NOARG(MAP_CTRL_METHOD_GET_VERSION_NAME, map_ctrl_get_version),
	UBUS_METHOD(MAP_CTRL_METHOD_SET_CONFIG_NAME, map_ctrl_set_configs, map_ctrl_configs_policy),
	UBUS_METHOD(MAP_CTRL_METHOD_GET_CONFIG_NAME, map_ctrl_get_configs, map_ctrl_configs_policy),
	UBUS_METHOD(MAP_CTRL_METHOD_TEST_NAME, map_ctrl_test, map_ctrl_test_policy),
};

static struct ubus_object_type map_ctrl_obj_type =
	UBUS_OBJECT_TYPE(MAP_CTRL_OBJ_NAME, map_ctrl_methods);

static struct ubus_object map_ctrl_obj = {
	.name = MAP_CTRL_OBJ_NAME,
	.type = &map_ctrl_obj_type,
	.methods = map_ctrl_methods,
	.n_methods = ARRAY_SIZE(map_ctrl_methods),
};

int map_ctrl_init(void)
{
	int ret;

	MAP_DEBUG("Add map ubus %s object\n", map_ctrl_obj.name);
	ret = ubus_add_object(g_ctx.ubus_ctx, &map_ctrl_obj);
	if (ret) {
		MAP_ERROR("Failed to add ubus %s object: %s\n",
			map_ctrl_obj.name, ubus_strerror(ret));
		return -1;
	}

	blob_buf_init(&b, 0);

	return 0;
}

void map_ctrl_deinit(void)
{
	blob_buf_free(&b);
}
