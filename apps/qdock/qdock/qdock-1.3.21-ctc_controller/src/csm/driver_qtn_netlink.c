/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include "csm.h"


#define NAME "driver.qtn.netlink"
#define PPREFIX "[Radio - "NAME"]: "
#define NLMSG_MAX_SIZE	(1024 * 36)

struct qnetlink_desc {
	struct csm_plugin_file_desc desc;
	struct csm_drv_plugin *plugin[1];
};

struct qnetlink_data {
	struct bsa_netlink_config *cfg;
	int drv_read_sock;
	int read_sock;
	int write_sock;
};

struct qnetlink_ctx {
	void *ctx;
	int running;
	pthread_t thread;
	struct qnetlink_data *nl_data;
};

static int qnetlink_action(void *ctx, csmmsg_t * action);

static void qnetlink_destroy_socks(struct qnetlink_data *netlink)
{
	if (netlink == NULL)
		return;

	if (netlink->read_sock >= 0) {
		close(netlink->read_sock);
	}
	if (netlink->write_sock >= 0) {
		close(netlink->write_sock);
	}

	CSM_FREE(netlink);
}

static struct
qnetlink_data *qnetlink_create_socks(void)
{
	struct qnetlink_data *netlink;
	struct sockaddr_nl local;
	int rxbuf = CSM_RPE_RCVBUF_SIZE;

	netlink = (void *) CSM_MALLOC(sizeof(struct qnetlink_data));
	if (netlink == NULL)
		goto fail;

	netlink->read_sock = -1;
	netlink->write_sock = -1;

	netlink->read_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (netlink->read_sock < 0) {
		CSM_DEBUG(PPREFIX "Failed to open netlink socket%s",
			  strerror(errno));
		goto fail;
	}

	if (setsockopt(netlink->read_sock, SOL_SOCKET,
		SO_RCVBUF, &rxbuf, sizeof(rxbuf)) < 0)
		CSM_WARNING("Failed to set netlink rcvbuf to %u: %s",
			rxbuf, strerror(errno));

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = RTMGRP_NOTIFY;

	if (bind
	    (netlink->read_sock, (struct sockaddr *) &local,
	     sizeof(local)) < 0) {
		CSM_DEBUG(PPREFIX "Failed to bind netlink socket%s",
			  strerror(errno));
		goto fail;
	}

	netlink->write_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (netlink->write_sock < 0) {
		CSM_DEBUG(PPREFIX "Failed to open netlink socket%s",
			  strerror(errno));
		goto fail;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_NOTIFY;

	if (bind
	    (netlink->write_sock, (struct sockaddr *) &local,
	     sizeof(local)) < 0) {
		CSM_DEBUG(PPREFIX "Failed to bind netlink socket%s",
			  strerror(errno));
		goto fail;
	}

	return netlink;
      fail:
	if (netlink)
		qnetlink_destroy_socks(netlink);
	return NULL;
}

static void qnetlink_single_msg_free(void *parent)
{
	csm_unref_msg((csmmsg_t *) parent);
}


static int qnetlink_process_peer_event(struct qnetlink_ctx *qnetlink,
				       csmmsg_t * parent, char *buf,
				       int len)
{
	csmmsg_t *msg = csm_new_empty_msg(0);
	if (msg) {

		csm_ref_msg(parent);
		csm_set_free_data((csmobj_t *) msg,
				  qnetlink_single_msg_free, parent);
		csm_msg_set_body(msg, buf, len);
		csm_push_event(qnetlink->ctx, msg);
		return 0;
	}
	return -1;
}

static int qnetlink_recv_peer_event(struct qnetlink_ctx *qnetlink)
{
	int len;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *nlh;

	int ret = -1;
	csmmsg_t *cmsg = csm_new_empty_msg(NLMSG_MAX_SIZE);
	char *buf;

	if (cmsg == NULL) {
		CSM_ERROR(PPREFIX "no memory");
		return -1;
	}
	buf = (char *) csm_get_msg_body(cmsg);

	iov = (struct iovec) {
	buf, NLMSG_MAX_SIZE};
	msg = (struct msghdr) {
	NULL, 0, &iov, 1, NULL, 0, 0};

	do {
		len = recvmsg(qnetlink->nl_data->read_sock, &msg, 0);
	} while (len < 0 && errno == EINTR);

	if (len <= 0) {
		CSM_DEBUG(PPREFIX "error reading netlink");
		goto fail;
	}

	for (nlh = (struct nlmsghdr *) buf; NLMSG_OK(nlh, len);
	     nlh = NLMSG_NEXT(nlh, len)) {
		/* The end of multipart message. */
		if (nlh->nlmsg_type == CSM_EVENT) {
			qnetlink_process_peer_event(qnetlink, cmsg,
						    (char *)
						    NLMSG_DATA(nlh),
						    NLMSG_PAYLOAD(nlh, 0));
			break;
		} else
			break;
	}
	ret = 0;
      fail:
	if (cmsg)
		csm_unref_msg(cmsg);
	return ret;
}

static int qnetlink_start(void *ctx)
{
	csmmsg_t *msg = csm_new_msg(CMD_INIT, CSM_VER_1, CSM_CODING_FIXED,
				    broadcast_ethaddr, sizeof(cmd_init_t));
	if (msg) {
		CSM_INFO("send start to RPE.");
		qnetlink_action(ctx, msg);
		csm_unref_msg(msg);
	}
	return 0;
}

static int qnetlink_stop(void *ctx)
{
	csmmsg_t *msg =
	    csm_new_msg(CMD_DEINIT, CSM_VER_1, CSM_CODING_FIXED,
			broadcast_ethaddr, sizeof(cmd_deinit_t));
	if (msg) {
		qnetlink_action(ctx, msg);
		csm_unref_msg(msg);
	}
	return 0;
}

static void *qnetlink_background_thread(void *ctx)
{
	struct qnetlink_ctx *qnetlink = (struct qnetlink_ctx *) ctx;

	qnetlink_start(ctx);

	while (qnetlink->running) {
		qnetlink_recv_peer_event(qnetlink);
	}

	qnetlink_stop(ctx);
	return NULL;
}

static void qnetlink_unload(void *ctx)
{
	struct qnetlink_ctx *qnetlink = (struct qnetlink_ctx *) ctx;
	if (qnetlink) {
		if (qnetlink->running) {
			qnetlink->running = 0;
			pthread_join(qnetlink->thread, NULL);
		}
		if (qnetlink->nl_data)
			qnetlink_destroy_socks(qnetlink->nl_data);

		CSM_FREE(ctx);
	}
}

static void *qnetlink_load(void *ctx)
{
	struct qnetlink_ctx *qnetlink =
	    CSM_CALLOC(1, sizeof(struct qnetlink_ctx));
	if (qnetlink) {
		memset(qnetlink, 0, sizeof(struct qnetlink_ctx));
		qnetlink->ctx = ctx;
		if (((qnetlink->nl_data =
		      qnetlink_create_socks())) == NULL)
			goto fail;
		qnetlink->running = 1;
		pthread_create(&qnetlink->thread, NULL,
			       qnetlink_background_thread, qnetlink);
	}
	return qnetlink;
      fail:
	qnetlink_unload(qnetlink);
	return NULL;
}

static int
qnetlink_send_cmd(struct qnetlink_data *netlink, char *raw_data, int len)
{
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct sockaddr_nl dest_addr;
	struct msghdr msg;

	nlh =
	    (struct nlmsghdr *) CSM_MALLOC(NLMSG_SPACE(NLMSG_LENGTH(len)));
	memset(nlh, 0, NLMSG_SPACE(NLMSG_LENGTH(len)));
	nlh->nlmsg_len = NLMSG_LENGTH(len);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = CSM_COMMAND;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	memcpy(NLMSG_DATA(nlh), raw_data, len);

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;	/* TODO: fill PID */
	dest_addr.nl_groups = RTMGRP_NOTIFY;	/*  */

	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *) &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(netlink->write_sock, &msg, 0) < 0) {
		CSM_DEBUG("sendmsg failed reason=%s", strerror(errno));
		CSM_FREE(nlh);
		return -1;
	}

	CSM_FREE(nlh);
	return 0;
}

static int qnetlink_action(void *ctx, csmmsg_t * action)
{
	struct qnetlink_ctx *qnetlink = (struct qnetlink_ctx *) ctx;
	csmmsgh_t *h = csm_get_msg_body(action);
	int len = le_to_host16(h->payload_len) + sizeof(csmmsgh_t);

	return qnetlink_send_cmd(qnetlink->nl_data, (char *) h, len);
}

static struct csm_drv_plugin qnetlink_plugin = {
	.plugin_head =
	    INIT_PLUGIN_HEAD(NAME, qnetlink_load, qnetlink_unload, NULL,
			     NULL),
	.ops = {
		.action = qnetlink_action,
		},
};

static struct qnetlink_desc g_qnetlink_desc = {
	.desc =
	    INIT_PLUGIN_FILE_DESC(CSM_DRIVER_MAGIC, CSM_DRIVER_VERSION, 1),
	.plugin[0] = &qnetlink_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *) &g_qnetlink_desc;
}
