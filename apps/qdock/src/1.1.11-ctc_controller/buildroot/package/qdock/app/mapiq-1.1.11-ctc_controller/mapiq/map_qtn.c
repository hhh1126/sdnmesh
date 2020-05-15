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
#include "map_server.h"
#include "map_ctrl.h"

#define PLUGIN_NAME "mapiq.qtn"

map_cfg_t g_cfg;
map_ctx_t g_ctx;

static int map_parse_type_value(map_event_t *event, int parse_type,
	csmmsgh_t *h)
{
	uint8_t *pos = h->payload;
	uint8_t *end = le_to_host16(h->payload_len) + pos;

	while (end - pos > sizeof(tlv_t)) {
		tlv_t *tag = (tlv_t *)pos;
		uint16_t type = le_to_host16(tag->type);
		uint16_t len = le_to_host16(tag->len);

		if (end - pos < (sizeof(tlv_t) + len))
			break;

		if (parse_type != type) {
			pos += (sizeof(tlv_t) + CSM_IE_LEN(len));
			continue;
		}
		switch (type) {
		case TLVTYPE_RADIO_MAC:
			MAP_MAC_COPY(event->u.radio, tag->value);
			return 0;
		case TLVTYPE_BSSID:
			MAP_MAC_COPY(event->u.sta, tag->value);
			return 0;
		case TLVTYPE_ROAM_FAIL:
			event->roam_result = tag->value[0];
			return 0;
		case TLVTYPE_RSSI_ADV:
			memcpy(event->rssi_adv, tag->value, RSSI_ADV_LEN);
			return 0;
		default:
			MAP_WARN("Unexpected tlv parsing type : %d.", type);
			break;
		}
	}

	return -1;
}

static int map_get_intf_status_changed(csmmsgh_t *h)
{
	uint32_t status = le_to_host32(((evt_intf_status_t *)h)->status);
	int intf_state = MAP_BSS_INTF_STATE_UNKNOWN;

	switch (status) {
	case RPE_INTF_STATE_UP:
		intf_state = MAP_BSS_INTF_STATE_UP;
		break;
	case RPE_INTF_STATE_DOWN:
	case RPE_INTF_STATE_NONAVAILABLE:
		intf_state = MAP_BSS_INTF_STATE_DOWN;
		break;
	case RPE_INTF_STATE_DELETED:
		intf_state = MAP_BSS_INTF_STATE_DELETED;
		break;
	default:
		MAP_ERROR("Unkown state = %d for BSS.",
			status);
		break;
	}
	return intf_state;
}

static void map_dump_cfg(void)
{
	/* TODO: dump the configuration */
}

static void map_init_def_cfg(void)
{
	pthread_mutex_init(&g_cfg.ifcfg_mutex, NULL);
	g_cfg.ifcfg_head = (struct list_head)LIST_HEAD_INIT(g_cfg.ifcfg_head);
}

static void map_load_cfg(void)
{
	csm_param_value value;
	if (csm_param_get_value(g_ctx.ctx, &value,
		"log_level", CSM_PARAM_STRING, -1) == 0)
		map_set_log_level(value.str_value);

	if (csm_param_get_value(g_ctx.ctx, &value,
		"fronthaul_iface", CSM_PARAM_STRING, -1) == 0)
		map_load_intf_config(value.str_value, 1, 0);

	if (csm_param_get_value(g_ctx.ctx, &value,
		"backhaul_iface", CSM_PARAM_STRING, -1) == 0)
		map_load_intf_config(value.str_value, 0, 1);

	if (csm_param_get_value(g_ctx.ctx, &value,
			"fat_monitor_period", CSM_PARAM_INT, -1) == 0)
			map_start_fat_monitoring_timer(value.int_value);
	else
		map_start_fat_monitoring_timer(30);

	if (csm_param_get_value(g_ctx.ctx, &value,
			"stat_monitor_period", CSM_PARAM_INT, -1) == 0)
			map_start_stat_monitoring_timer(value.int_value);
	else
		map_start_stat_monitoring_timer(2);
}

static void map_init_cfg(void)
{
	map_init_def_cfg();

	map_load_cfg();

	map_dump_cfg();
}

static int map_build_sta_connected_event(map_event_t *event,
	csmmsgh_t *h, int is_sta_mode)
{
	evt_connect_complete_t *evt_connected = (evt_connect_complete_t *)h;

	if (MAP_MAC_IS_NULL(evt_connected->sta_mac))
		return -1;

	MAP_DEBUG("peer %s mac:"MAP_MACFMT"\n",
		is_sta_mode ? "bss" : "sta",
		MAP_MACARG(evt_connected->sta_mac));
	MAP_MAC_COPY(event->dev_id, h->bssid);
	MAP_MAC_COPY(event->u.sta, evt_connected->sta_mac);
	if (is_sta_mode) {
		event->id = MAP_EVENT_WDEV_ASSOCIATED;
		event->roam_result = 0;
	}
	else
		event->id = MAP_EVENT_STA_CONNECTED;

	return 0;
}

static int map_build_sta_disconnected_event(map_event_t *event,
	csmmsgh_t *h)
{
	evt_disassoc_t *evt_disconnected = (evt_disassoc_t *)h;

	if (MAP_MAC_IS_NULL(evt_disconnected->sta_mac))
		return -1;

	MAP_MAC_COPY(event->dev_id, h->bssid);
	MAP_MAC_COPY(event->u.sta, evt_disconnected->sta_mac);
	event->id = MAP_EVENT_STA_DISCONNECTED;

	return 0;
}

static int map_build_wdev_roam_fail_event(map_event_t *event,
	csmmsgh_t *h)
{
	if (map_parse_type_value(event, TLVTYPE_BSSID, h) < 0)
		return -1;
	if (map_parse_type_value(event, TLVTYPE_ROAM_FAIL, h) < 0)
		return -1;
	MAP_MAC_COPY(event->dev_id, h->bssid);
	event->id = MAP_EVENT_WDEV_ASSOCIATED;
	return 0;
}

static int map_build_radio_updated_event(map_event_t *event,
	csmmsgh_t *h)
{
	if (map_parse_type_value(event, TLVTYPE_RADIO_MAC, h) < 0)
		return -1;
	event->id = MAP_EVENT_WIPHY_UPDATED;
	return 0;
}

static int map_build_bss_updated_event(map_event_t *event,
	csmmsgh_t *h)
{
	event->id = MAP_EVENT_WDEV_UPDATED;
	MAP_MAC_COPY(event->dev_id, h->bssid);
	return 0;
}

static int map_build_bss_state_updated_event(map_event_t *event,
	csmmsgh_t *h, int state_changed)
{
	event->id = MAP_EVENT_WDEV_STATE_UPDATED;
	MAP_MAC_COPY(event->dev_id, h->bssid);
	event->state = (state_changed == MAP_BSS_INTF_STATE_UP) ? 1 : 0;
	return 0;
}

static int map_build_bss_deleted_event(map_event_t *event,
	csmmsgh_t *h)
{
	event->id = MAP_EVENT_WDEV_DELETED;
	MAP_MAC_COPY(event->dev_id, h->bssid);
	return 0;
}

static int map_build_frame_recv_event(map_event_t *event,
	csmmsgh_t *h)
{
	uint16_t payload_len = le_to_host16(h->payload_len);
	uint8_t *payload;

	if (map_parse_type_value(event, TLVTYPE_RSSI_ADV, h) < 0)
		return -1;

	payload = map_parse_frame(h->payload, payload_len,
		&event->frame_len );
	if (!payload)
		return -1;

	event->id = MAP_EVENT_FRAME_RECEIVED;
	MAP_MAC_COPY(event->dev_id, h->bssid);

	event->frame = (uint8_t *)MAP_MALLOC(event->frame_len);
	if (!event->frame)
		return -1;

	memcpy(event->frame, payload, event->frame_len);

	return 0;
}

void map_send_event(map_event_t *evt)
{
	map_event_t *event;

	MAP_DEBUG("Send event %u\n", evt->id);

	event = MAP_MALLOC(sizeof(*evt));
	if (!event)
		return;

	memcpy(event, evt, sizeof(*event));
	pthread_mutex_lock(&g_ctx.evt_mutex);
	list_add_tail(&event->lh, &g_ctx.evt_head);
	pthread_mutex_unlock(&g_ctx.evt_mutex);

	if (g_ctx.evt_txfd >= 0) {
		if (write(g_ctx.evt_txfd, &event->id, sizeof(event->id)) < 0)
			MAP_ERROR("Failed to write evt_txfd: %s\n", strerror(errno));
	}
}

static struct map_event *map_get_event(void)
{
	map_event_t *event = NULL;

	pthread_mutex_lock(&g_ctx.evt_mutex);
	if (!list_empty(&g_ctx.evt_head)) {
		event = list_first_entry(&g_ctx.evt_head, struct map_event, lh);
		list_del(&event->lh);
	}
	pthread_mutex_unlock(&g_ctx.evt_mutex);

	return event;
}

static void map_process_event(struct uloop_fd *fd, unsigned int events)
{
	int id, n;
	map_event_t *event;

	MAP_DEBUG("Process events\n");

	while ((n = read(g_ctx.evt_rxfd, &id, sizeof(id))) > 0);

	while (NULL != (event = map_get_event())) {
		map_notify_event(event);
		MAP_FREE(event);
	}
}

static void *map_main_thread(void *ctx)
{
	struct uloop_fd rxfd = {
		.fd = g_ctx.evt_rxfd,
		.cb = map_process_event,
	};

	g_ctx.running = 1;

	map_init_cfg();
	uloop_init();

	uloop_fd_add(&rxfd, ULOOP_READ);

	if (map_service_init() >= 0)
		uloop_run();

	MAP_INFO("MAPiQ main thread end\n");

	map_del_all_intf_config();

	map_service_deinit();

	uloop_done();

	return NULL;
}

static inline void map_destroy_event(map_event_t *event)
{
	list_del(&event->lh);
	MAP_FREE(event);
}

static void map_free_event_list(void)
{
	pthread_mutex_lock(&g_ctx.evt_mutex);
	while (!list_empty(&g_ctx.evt_head)) {
		map_event_t *event = list_first_entry(&g_ctx.evt_head, struct map_event, lh);
		map_destroy_event(event);
	}
	pthread_mutex_unlock(&g_ctx.evt_mutex);
}

static void map_init_context(void)
{
	int fds[2];

	memset(&g_ctx, 0, sizeof(g_ctx));
	MAP_LOG_INIT(LOG_WARNING);

	pthread_mutex_init(&g_ctx.evt_mutex, NULL);
	g_ctx.evt_head = (struct list_head)LIST_HEAD_INIT(g_ctx.evt_head);
	g_ctx.evt_rxfd = -1;
	g_ctx.evt_txfd = -1;

	if (pipe(fds)) {
		MAP_ERROR("Failed to create pipe: %s\n", strerror(errno));
		return;
	}

	g_ctx.evt_rxfd = fds[0];
	g_ctx.evt_txfd = fds[1];
}

static void map_deinit_context(void)
{
	map_free_event_list();

	if (g_ctx.evt_rxfd >= 0)
		close(g_ctx.evt_rxfd);
	if (g_ctx.evt_txfd >= 0)
		close(g_ctx.evt_txfd);

	g_ctx.evt_rxfd = -1;
	g_ctx.evt_txfd = -1;
}

static void *map_load(void *ctx)
{
	if (g_ctx.ctx) {
		MAP_ERROR("Failed to attach Q-MAP: already attached\n");
		return NULL;
	}

	map_init_context();
	g_ctx.ctx = ctx;

	if (pthread_create(&g_ctx.thread, NULL, map_main_thread, NULL)) {
		MAP_ERROR("Failed to attach Q-MAP: %s\n",
			strerror(errno));
		return NULL;
	}

	MAP_INFO("Q-MAP attached\n");

	return &g_ctx;
}

static void map_unload(void *ctx)
{
	MAP_INFO("Begin unload Q-MAP lib\n");
	if (g_ctx.running) {
		g_ctx.running = 0;
		uloop_end();
		pthread_join(g_ctx.thread, NULL);
	}

	map_deinit_context();
	g_ctx.ctx = NULL;

	MAP_INFO("End unload Q-MAP lib\n");
}

static int map_recv_event(void *ctx, csmmsg_t *event)
{
	csmmsgh_t *h;
	uint16_t id;
	map_event_t map_event;
	int intf_state_changed, ret = -1;
	bss_table_t *bss;

	if (NULL == ctx
		|| ctx != &g_ctx
		|| NULL == (h = csm_get_msg_body(event))) {
		MAP_ERROR("Recv event, but param is null (%p, %p)\n",
			ctx, event);
		return -1;
	}

	id = le_to_host16(h->id);

	switch (id) {
	case EVENT_CONNECT_COMPLETE:
		bss = map_get_stadb_bss(h->bssid);
		if (!bss) {
			MAP_ERROR("bss of "MAP_MACFMT" not in talbe list!\n",
				MAP_MACARG(h->bssid));
			return -1;
		}
		if (bss->iftype == NODE_TYPE_VAP)
			ret = map_build_sta_connected_event(&map_event, h, 0);
		else if (bss->iftype == NODE_TYPE_STA)
			ret = map_build_sta_connected_event(&map_event, h, 1);
		map_stadb_stah_unref((stah_t *)bss);
		break;
	case EVENT_DISASSOC:
	case EVENT_DEAUTH:
		bss = map_get_stadb_bss(h->bssid);
		if (!bss) {
			MAP_ERROR("bss of "MAP_MACFMT" not in talbe list!\n",
				MAP_MACARG(h->bssid));
			return -1;
		}
		if (bss->iftype == NODE_TYPE_VAP)
			ret = map_build_sta_disconnected_event(&map_event, h);
		map_stadb_stah_unref((stah_t *)bss);
		break;
	case EVENT_ROAM_FAIL:
		ret = map_build_wdev_roam_fail_event(&map_event, h);
		break;
	case EVENT_RADIO_INFO:
	case EVENT_RADIO_STATUS:
		ret = map_build_radio_updated_event(&map_event, h);
		break;
	case EVENT_INTF_INFO:
		ret = map_build_bss_updated_event(&map_event, h);
		break;
	case EVENT_INTF_STATUS:
		intf_state_changed =  map_get_intf_status_changed(h);
		if (intf_state_changed == MAP_BSS_INTF_STATE_UP)
			map_init_wdev(h->bssid);
		if ((intf_state_changed == MAP_BSS_INTF_STATE_UP) ||
			(intf_state_changed == MAP_BSS_INTF_STATE_DOWN))
			ret = map_build_bss_state_updated_event(&map_event, h, intf_state_changed);
		else if (intf_state_changed == MAP_BSS_INTF_STATE_DELETED)
			ret = map_build_bss_deleted_event(&map_event, h);
		break;
	case EVENT_FRAME:
		ret = map_build_frame_recv_event(&map_event, h);
	default:
		break;
	}

	if (ret == 0)
		map_send_event(&map_event);

	return ret;
}

struct map_desc {
	struct csm_plugin_file_desc desc;
	struct csm_logic_plugin *plugin[1];
};

static struct csm_logic_plugin map_plugin = {
	.plugin_head = INIT_PLUGIN_HEAD(PLUGIN_NAME, map_load, map_unload, NULL, NULL),
	.type = LOGIC_ROLE_STEERING,
	.ops = {
		.recv_event = map_recv_event,
	},
};

static struct map_desc g_map_desc = {
	.desc = INIT_PLUGIN_FILE_DESC(CSM_LOGIC_MAGIC, CSM_LOGIC_VERSION, 1),
	.plugin[0] = &map_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *) &g_map_desc;
}

void __attribute__((destructor)) map_fini(void)
{
	printf("MAPiQ-%s(%s-%s) lib unloaded\n", PLUGIN_NAME, MAPIQ_VERSION, MAPIQ_SUBVERSION);
}

void __attribute__((constructor)) map_init(void)
{
	memset(&g_ctx, 0, sizeof(g_ctx));
	printf("MAPiQ-%s(%s-%s) lib loaded\n", PLUGIN_NAME, MAPIQ_VERSION, MAPIQ_SUBVERSION);
}
