/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          		 **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include "spdia_qtn.h"
#include "spdia_cli.h"
#include "spdia_dbg.h"

#define PLUGIN_NAME "spdia.qtn"

static spdia_info_t g_spdia_buf;
uint8_t *csi_payload; /*!<csi payload */

static inline void spdia_init_buf(void)
{
	spdia_head_t *head = (spdia_head_t *)&g_spdia_buf;
#ifdef PLATFORM_PEARL
	memcpy(head->magic, "QCETAPI1", SPDIA_MAGIC_LEN);
#else
	memcpy(head->magic, "QCETAPI0", SPDIA_MAGIC_LEN);
#endif
	head->type = 1;
}

static inline void spdia_reset_buf(void)
{
	spdia_head_t *head = (spdia_head_t *)&g_spdia_buf;
	head->size = sizeof(spdia_info_t);
	memset(head + 1, 0, sizeof(spdia_info_t) - sizeof(*head));
	csi_payload = NULL;
}

static inline spdia_info_t *spdia_get_info(void)
{
	spdia_reset_buf();
	return (spdia_info_t *)&g_spdia_buf;
}

static inline void spdia_put_info(spdia_info_t *info)
{
	return;
}

spdia_ctx_t g_ctx;

static void spdia_init_cfg(void)
{
#if defined (SPDIA_SUPPORT_TCP_DUMP) || defined (SPDIA_SUPPORT_FILE_DUMP)
	spdia_init_dump_cfg();
#endif

	pthread_mutex_init(&g_ctx.sta_mutex, NULL);
	g_ctx.sta_head = (struct list_head)LIST_HEAD_INIT(g_ctx.sta_head);

	spdia_load_cfg();
}

static inline void spdia_add_fdset(int fd, fd_set *fdset, int *maxfd)
{
	if (fd < 0)
		return;
	FD_SET(fd, fdset);
	if (maxfd && *maxfd < fd)
		*maxfd = fd;
}

static void *spdia_main_thread(void *ctx)
{
	fd_set readset;

	g_ctx.running = 1;
	spdia_init_buf();
	spdia_init_cfg();

#if defined (SPDIA_SUPPORT_TCP_DUMP) || defined (SPDIA_SUPPORT_FILE_DUMP)
	spdia_dump_init();
#endif

	while (g_ctx.running) {
		int max_sd = -1;
		FD_ZERO(&readset);
		spdia_add_fdset(g_ctx.ctrl_sock, &readset, &max_sd);

#ifdef SPDIA_SUPPORT_TCP_DUMP
		spdia_add_fdset(g_ctx.dump_server_sock, &readset, &max_sd);

		pthread_mutex_lock(&g_ctx.dump_mutex);
		spdia_add_fdset(g_ctx.dump_client_sock, &readset, &max_sd);
		pthread_mutex_unlock(&g_ctx.dump_mutex);
#endif

		if (select(max_sd + 1, &readset, 0, 0, NULL) < 0) {
			if (errno == EAGAIN) {
				continue;
			} else if (errno != EINTR
				&& errno != EBADF) {
				SPDIA_WARN("main thread failed(%d): %s\n",
					errno, strerror(errno));
				break;
			}
		}

#ifdef SPDIA_SUPPORT_TCP_DUMP
		pthread_mutex_lock(&g_ctx.dump_mutex);
		if (g_ctx.dump_client_sock >= 0
			&& FD_ISSET(g_ctx.dump_client_sock, &readset))
			spdia_recv_dump_client();
		pthread_mutex_unlock(&g_ctx.dump_mutex);

		if (g_ctx.dump_server_sock >= 0
			&& FD_ISSET(g_ctx.dump_server_sock, &readset))
			spdia_recv_dump_connect();
#endif

		if (g_ctx.ctrl_sock >= 0
			&& FD_ISSET(g_ctx.ctrl_sock, &readset))
			spdia_recv_ctrl_frame(&g_ctx);
	}

	return NULL;
}

static void *spdia_load(void *ctx)
{
	if (NULL == ctx) {
		SPDIA_ERROR("fail to load spdia: ctx is null\n");
		return NULL;
	}

	if (g_ctx.ctx) {
		SPDIA_ERROR("fail to load spdia: already loaded, only support one instance\n");
		return NULL;
	}

	g_ctx.ctx = ctx;
	if (pthread_create(&g_ctx.thread, NULL, spdia_main_thread, NULL)) {
		SPDIA_ERROR("fail to load spdia: create main thread failed\n");
		return NULL;
	}

	SPDIA_DEBUG("spdia loaded\n");

	return &g_ctx;
}

static void spdia_unload(void *ctx)
{
	spdia_ctx_t *spdia_ctx = (spdia_ctx_t *)ctx;
	if (NULL == ctx) {
		SPDIA_ERROR("unload spdia ctx is null\n");
		return;
	}

	if (!spdia_ctx->ctx) {
		SPDIA_ERROR("unload spdia ctx is not loaded\n");
		return;
	}

	spdia_ctx->ctx = NULL;

	if (spdia_ctx->running) {
		spdia_ctx->running = 0;
		pthread_join(spdia_ctx->thread, NULL);
	}
#if defined (SPDIA_SUPPORT_TCP_DUMP) || defined (SPDIA_SUPPORT_FILE_DUMP)
	spdia_dump_deinit();
#endif
}

int spdia_update_diagnosed_sta(uint8_t *mac, uint16_t period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth)
{
	if (spdia_ctrl(g_ctx.ctx, mac, period, reorder,
		mode, ng, smooth) < 0) {
		SPDIA_WARN("ctrl diagnosed sta " SPDIA_MACFMT
			" failed\n", SPDIA_MACARG(mac));
		return -1;
	}

	if (period != 0)
		SPDIA_INFO("ctrl diagnosed sta " SPDIA_MACFMT
			" to report CSI event per %u ms reorder %d "
			"mode %d ng %d smooth %d\n", SPDIA_MACARG(mac),
			period,reorder, mode, ng, smooth);
	else
		SPDIA_INFO("remove diagnosed sta " SPDIA_MACFMT
			" from CSI monitoring\n", SPDIA_MACARG(mac));

	return 0;
}

static void spdia_deal_connect_complete(spdia_ctx_t *spdia_ctx, csmmsgh_t *h)
{
	spdia_sta_cfg_t *sta = NULL;
	uint16_t period = 0;
	int found = 0;

	evt_connect_complete_t *evt_connected
		= (evt_connect_complete_t *)h;

	pthread_mutex_lock(&spdia_ctx->sta_mutex);
	list_for_each_entry(sta, &spdia_ctx->sta_head, lh) {
		if (SPDIA_MAC_EQ(sta->mac, evt_connected->sta_mac)) {
			period = sta->period;
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&g_ctx.sta_mutex);

	if (found && sta) {
		spdia_update_diagnosed_sta(evt_connected->sta_mac, period,
			sta->reorder, sta->mode, sta->ng, sta->smooth);
	}
	else {
		bss_table_t *bss = spdia_get_stadb_bss(spdia_ctx->ctx, h->bssid);
		if (!bss)
			return;

		if (bss->iftype == NODE_TYPE_STA)
			spdia_update_diagnosed_sta(evt_connected->sta_mac, 50, 1, 1, 1, 0);

		spdia_stadb_stah_unref((stah_t *)bss);
	}
}

static int spdia_parse_info_event(spdia_info_t *info, csmmsgh_t *h, uint32_t *data_index)
{
	uint8_t *pos = h->payload;
	uint8_t *end = le_to_host16(h->payload_len) + pos;

	while (end - pos > sizeof(tlv_t)) {
		uint32_t i;
		tlv_t *tag = (tlv_t *)pos;
		uint16_t type = le_to_host16(tag->type);
		uint16_t len = le_to_host16(tag->len);

		if (end - pos < (sizeof(tlv_t) + len))
			break;

		switch (type) {
		case TLVTYPE_STA_MAC:
			if (len < ETH_ALEN) {
				SPDIA_ERROR("spdia info parsing failed: "
					"sta mac len(%u) less than 6\n", len);
				return -1;
			}
			SPDIA_MAC_COPY(info->mac, tag->value);
			break;

		case TLVTYPE_TS_LAST_RX:
			info->timestamp = extract_host64(tag->value[0]);
			break;

		case TLVTYPE_RSSI_VECTOR:
			for (i = 0; i < (len >> 2)
				&& i < SPDIA_CHAINS; i+= 1)
				info->rssis[i] = extract_host32(tag->value[i * 4]);
			break;

		case TLVTYPE_NOISE:
			if (len < 4) {
				SPDIA_ERROR("spdia info parsing failed: "
					"noise len(%u) less than 4\n", len);
				return -1;
			}
			info->hw_noise = extract_host32(tag->value[0]);
			break;

		case TLVTYPE_SPDIA_CONF:
			if (len < 4) {
				SPDIA_ERROR("spdia info parsing failed: "
					"conf len(%u) less than 4\n", len);
				return -1;
			}
			info->nc = tag->value[0];
			info->nr = tag->value[1];
			info->ng = tag->value[2];
			break;

		case TLVTYPE_SPDIA_TONES:
			if (len < 4) {
				SPDIA_ERROR("spdia info parsing failed: "
					"tones len(%u) less than 4\n", len);
				return -1;
			}
			info->ntones = extract_host32(tag->value[0]);
			break;

		case TLVTYPE_SPDIA_DATA_INDEX:
			if (len < 4) {
				SPDIA_ERROR("spdia info parsing failed: "
					"data_index len(%u) less than 4\n", len);
				return -1;
			}
			*data_index = extract_host32(tag->value[0]);
			break;

		case TLVTYPE_SPDIA_DETAILS:
			if (len < 4) {
				SPDIA_ERROR("spdia info parsing failed: "
					"details len(%u) less than 4\n", len);
				return -1;
			}
			info->chan = tag->value[0];
			info->bw = tag->value[1] & 0x0f;
			info->bf_mode = tag->value[1] >> 4;
			info->mcs = tag->value[2];
			info->mcs_ss = tag->value[3];
			break;

		case TLVTYPE_SPDIA_PAYLOAD:
			csi_payload = tag->value;
			info->head.size = len + sizeof(*info);
			break;

		default:
			break;
		}

		pos += (sizeof(tlv_t) + CSM_IE_LEN(len));
	}

	if (pos != end) {
		SPDIA_WARN("spdia info parsing failed: len is not correct\n");
		return -1;
	}

	return 0;
}

static int spdia_deal_info_event(spdia_ctx_t *spdia_ctx, csmmsgh_t *h)
{
	int ret = -1;
	static uint32_t last_data_index = 0;
	uint32_t data_index = 0;
	spdia_info_t *info = spdia_get_info();
	if (!info)
		return -1;

	ret = spdia_parse_info_event(info, h, &data_index);
	if (ret < 0) {
		SPDIA_ERROR("spdia info parsing failed\n");
		spdia_put_info(info);
		return -1;
	}

	if (data_index && data_index != (last_data_index+1))
		fprintf(stderr, "*** [ERROR] [QSPDIA] mis-match CSI data index last_idx:%d"
			" currect_idx:%d ***\n", last_data_index, data_index);
	last_data_index = data_index;
#if defined (SPDIA_SUPPORT_TCP_DUMP) || defined (SPDIA_SUPPORT_FILE_DUMP)
	spdia_dump_info(info, csi_payload, h);
#endif

	spdia_put_info(info);
	return 0;
}

static int spdia_recv_event(void *ctx, csmmsg_t *event)
{
	spdia_ctx_t *spdia_ctx = (spdia_ctx_t *)ctx;
	csmmsgh_t *h;
	uint16_t id;

	if(NULL == spdia_ctx
		|| NULL == event
		|| NULL == (h = csm_get_msg_body(event))) {
		SPDIA_ERROR("recv event, but param is null (%p, %p)\n", ctx, event);
		return -1;
	}

	id = le_to_host16(h->id);
	switch(id) {
	case EVENT_CONNECT_COMPLETE:
		spdia_deal_connect_complete(spdia_ctx, h);
		break;

	case EVENT_SPDIA_INFO:
		spdia_deal_info_event(spdia_ctx, h);
		break;

	default:
		break;
	}

	return 0;
}

struct spdia_desc {
	struct csm_plugin_file_desc desc;
	struct csm_logic_plugin *plugin[1];
};

static struct csm_logic_plugin spdia_plugin = {
	.plugin_head = INIT_PLUGIN_HEAD(PLUGIN_NAME, spdia_load, spdia_unload, NULL, NULL),
	.type = LOGIC_ROLE_SPDIA,
	.ops = {
		.recv_event = spdia_recv_event,
	},
};

static struct spdia_desc g_spdia_desc = {
	.desc = INIT_PLUGIN_FILE_DESC(CSM_LOGIC_MAGIC, CSM_LOGIC_VERSION, 1),
	.plugin[0] = &spdia_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *)&g_spdia_desc;
}

static int spdia_create_ctrl_sock(void)
{
	int sd;
	struct sockaddr_un addr;

	if ((sd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		SPDIA_ERROR("ctrl sock failed: %s\n", strerror(errno));
		return -1;
	}

	unlink(SPDIA_UNIX_PATH);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SPDIA_UNIX_PATH);
	if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		SPDIA_ERROR("ctrl sock failed: %s\n", strerror(errno));
		close(sd);
		return -1;
	}

	return sd;
}

void __attribute__((destructor)) spdia_fini(void)
{
	SPDIA_INFO("begin unload Q-SPDIA lib\n");

	if (g_ctx.ctrl_sock > 0)
		close(g_ctx.ctrl_sock);
	if (g_ctx.running) {
		g_ctx.running = 0;
		pthread_kill(g_ctx.thread, SIGUSR2);
		pthread_join(g_ctx.thread, NULL);
	}
	return;
}

void __attribute__((constructor)) spdia_init(void)
{
	memset(&g_ctx, 0, sizeof(g_ctx));
	SPDIA_LOG_INIT(LOG_DEBUG);

	g_ctx.ctrl_sock = spdia_create_ctrl_sock();

	SPDIA_INFO("loaded Q-SPDIA lib\n");

	return;
}
