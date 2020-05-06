/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.                  **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/

#include "qsteer.h"

struct comm_desc {
	struct csm_plugin_file_desc desc;
	struct csm_comm_plugin *plugin[1];
};

struct comm_ctx {
	void *ctx;
	qsteer_connect_complete_t sl_cbk_connect_complete;
	qsteer_bss_trans_status_t sl_cbk_bss_trans_status;
};

static struct comm_ctx *g_comm_ctx;

static int comm_get_role(void)
{
	return 0;
}

static int comm_deauth(uint8_t * bss, uint8_t * sta, uint16_t code,
		       int blacklist)
{
	if (!g_comm_ctx)
		return -1;

	return Steer_CSM_deauth(g_comm_ctx->ctx, bss, sta, code,
				blacklist);
}

static int comm_bss_trans_req(uint8_t * bss, uint8_t * payload,
			      uint32_t payload_len)
{
	if (!g_comm_ctx)
		return -1;

	return QSteer_CSM_BssTransReq(g_comm_ctx->ctx, bss, payload,
				      payload_len);
}

static void comm_unload(void *ctx)
{
	if (ctx)
		free(ctx);
	g_comm_ctx = NULL;
}

static void *comm_load(void *ctx)
{
	struct comm_ctx *comm;

	comm = calloc(1, sizeof(struct comm_ctx));
	if (!comm)
		return NULL;

	comm->ctx = ctx;
	g_comm_ctx = comm;

	return comm;
}

static int comm_notify_sl_connect_complete(struct comm_ctx *comm, uint8_t *mdid, uint8_t *bss, uint8_t *sta)
{
	if (!comm->sl_cbk_connect_complete)
		return -1;

	return comm->sl_cbk_connect_complete(mdid, bss, sta);
}

static int comm_notify_sl_bss_trans_status(struct comm_ctx *comm, uint8_t *mdid, uint8_t *sta, uint8_t status)
{
	if (!comm->sl_cbk_bss_trans_status)
		return -1;

	return comm->sl_cbk_bss_trans_status(mdid, sta, status);
}

static int comm_connect_complete(uint8_t *mdid, uint8_t *bss, uint8_t *sta)
{
	struct comm_ctx *comm = g_comm_ctx;

	if (!comm || !bss || !sta)
		return -1;

	return comm_notify_sl_connect_complete(comm, mdid, bss, sta);
}

static int comm_bss_trans_status(uint8_t *mdid, uint8_t *sta, uint8_t status)
{
	struct comm_ctx *comm = g_comm_ctx;

	if (!comm || !sta)
		return -1;

	return comm_notify_sl_bss_trans_status(comm, mdid, sta, status);
}

static int comm_register_clbks(qsteer_connect_complete_t sl_cbk_connect_complete,
		qsteer_bss_trans_status_t sl_cbk_bss_trans_status,
		qsteer_tables_sync_t sl_cbk_tables_sync,
		qsteer_recv_rpe_t sl_cbk_recv_rpe)
{
	struct comm_ctx *comm = g_comm_ctx;

	if (!comm)
		return -1;

	comm->sl_cbk_connect_complete = sl_cbk_connect_complete;
	comm->sl_cbk_bss_trans_status = sl_cbk_bss_trans_status;

	return 0;
}

static struct csm_comm_plugin comm_plugin = {
	.plugin_head =
	    INIT_PLUGIN_HEAD("comm.qtn.inactive", comm_load, comm_unload,
			     NULL, NULL),
	.ops = {
		.action = NULL,
		.get_role = comm_get_role,
		.connect_complete = comm_connect_complete,
		.deauth = comm_deauth,
		.bss_trans_req = comm_bss_trans_req,
		.bss_trans_status = comm_bss_trans_status,
		.register_clbks = comm_register_clbks,
	},
};

static struct comm_desc g_comm_desc = {
	.desc = INIT_PLUGIN_FILE_DESC(CSM_COMM_MAGIC, CSM_COMM_VERSION, 1),
	.plugin[0] = &comm_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *) &g_comm_desc;
}
