/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016, 2019 Quantenna Communications, Inc.           **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <errno.h>
#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/genetlink.h>


#include "csm.h"

#define NAME "driver.qtn.gennl"
#define PPREFIX "[Radio - "NAME"]: "

#define GENLMSG_MAX_SIZE	(1024 * 36)

#define CSM_DRIVER_EVENT	"qrpe_drv_event"
#define CSM_APP_COMMAND	"qrpe_app_cmd"
#define CSM_PEER_EVENT	"qrpe_app_event"

#define CSM_FAMILY_NAME	"qrpe_family"


enum {
	CSM_GENL_DRV_EVENT		= 0x11,
	CSM_GENL_APP_CMD		= 0x12,
	CSM_GENL_DRV_APP_CMD		= 0x13,
	CSM_GENL_PEER_EVENT		= 0x14,
	CSM_GENL_DRV_PEER_EVENT	= 0x15,
};

enum nl80211_attrs {
	CSM_ATTR_UNSPEC,
	CSM_ATTR_MSG_TYPE,
	CSM_ATTR_EVENT_DATA,
	CSM_ATTR_TX_APP_COMMAND,
	CSM_ATTR_RX_APP_COMMAND,
	CSM_ATTR_TX_PEER_EVENT,
	CSM_ATTR_RX_PEER_EVENT,

	__CSM_ATTR_AFTER_LAST,
	NUM_CSM_ATTR = __CSM_ATTR_AFTER_LAST,
};


typedef struct {
	int recv_buffer_size;
	struct nl_sock *send_sock;
	struct nl_sock *sock;
	int genl_fam_id;
} qgennl_link_t;



struct qgennl_desc {
	struct csm_plugin_file_desc desc;
	struct csm_drv_plugin *plugin[1];
};

typedef struct qgennl_ctx {
	void *ctx;
	int running;
	pthread_t thread;
	qgennl_link_t link;
} gennl_ctx_t;


static void qgennl_single_msg_free(void *parent)
{
	csm_unref_msg((csmmsg_t *) parent);
}

static int qgennl_process_peer_event(void *ctx,
	void *parent, char *buf, int len)
{
	struct qgennl_ctx *qgennl = (struct qgennl_ctx *)ctx;
	csmmsg_t *msg = csm_new_empty_msg(0);

	if (msg) {
		csm_ref_msg((csmmsg_t *)parent);
		csm_set_free_data((csmobj_t *) msg,
				  qgennl_single_msg_free, (csmmsg_t *)parent);
		csm_msg_set_body(msg, buf, len);
		csm_push_event(qgennl->ctx, msg);
		return 0;
	}
	return -1;
}


int qgennl_send_message(qgennl_link_t *link, const unsigned char *msg, unsigned int len)
{
	int ret = -1;
	struct nl_msg *nlmsg = NULL;
	uint32_t maxlen = nlmsg_total_size(nla_total_size(len)) + nlmsg_total_size(0);

	if(NULL == (nlmsg = nlmsg_alloc_size(maxlen))) {
		CSM_ERROR("nl msg \n");
		return ret;
	}

	if(NULL == genlmsg_put(nlmsg, 0, 0, link->genl_fam_id, 0, 0, CSM_GENL_APP_CMD, 0)) {
		CSM_ERROR("gen nl msg put failed\n");
		goto __return;
	}

	if(nla_put(nlmsg, CSM_ATTR_TX_APP_COMMAND, len, msg) < 0) {
		CSM_ERROR("gen nl attr put failed\n");
		goto __return;
	}

	if(nl_send_auto(link->send_sock, nlmsg) <= 0) {
		CSM_ERROR("nl send failed\n");
	}

	ret = 0;
__return:
	if(nlmsg)
		nlmsg_free(nlmsg);

	return ret;
}


static int qgennl_action(void *ctx, csmmsg_t * action)
{
	struct qgennl_ctx *qgennl = (struct qgennl_ctx *) ctx;
	csmmsgh_t *h = csm_get_msg_body(action);
	uint32_t len = le_to_host16(h->payload_len) + sizeof(csmmsgh_t);

	return qgennl_send_message(&qgennl->link, (uint8_t *)h, len);
}

static int qgennl_start(void *ctx)
{
	csmmsg_t *msg = csm_new_msg(CMD_INIT, CSM_VER_1, CSM_CODING_FIXED,
				    broadcast_ethaddr, sizeof(cmd_init_t));
	if (msg) {
		CSM_INFO("send start to RPE.");
		qgennl_action(ctx, msg);
		csm_unref_msg(msg);
	}
	return 0;
}

static int qgennl_stop(void *ctx)
{
	csmmsg_t *msg =
	    csm_new_msg(CMD_DEINIT, CSM_VER_1, CSM_CODING_FIXED,
			broadcast_ethaddr, sizeof(cmd_deinit_t));
	if (msg) {
		qgennl_action(ctx, msg);
		csm_unref_msg(msg);
	}
	return 0;
}

static void *qgennl_background_thread(void *ctx)
{
	struct qgennl_ctx *qgennl = (struct qgennl_ctx *)ctx;
	int fd, len;
	int ret, rxbuf = CSM_RPE_RCVBUF_SIZE;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr *nla;
	csmmsg_t *cmsg;
	char *buf;

	if((fd = nl_socket_get_fd(qgennl->link.sock)) < 0)
		return NULL;

	if (setsockopt(fd, SOL_SOCKET,
		SO_RCVBUF, &rxbuf, sizeof(rxbuf)) < 0)
		CSM_WARNING("Failed to set netlink rcvbuf to %u: %s",
			rxbuf, strerror(errno));

	qgennl_start(qgennl);

	while (qgennl->running) {
		fd_set readset;
		FD_ZERO(&readset);
		FD_SET(fd, &readset);

		if ((ret = select(fd + 1, &readset, 0, 0, NULL)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			CSM_ERROR("select failed %s", strerror(errno));
			break;
		}

		if (FD_ISSET(fd, &readset)) {
			cmsg = csm_new_empty_msg(GENLMSG_MAX_SIZE);
			if (cmsg == NULL) {
				CSM_ERROR(PPREFIX "no memory");
				goto fail;
			}
			buf = (char *) csm_get_msg_body(cmsg);

			iov = (struct iovec) {
			buf, GENLMSG_MAX_SIZE};
			msg = (struct msghdr) {
			NULL, 0, &iov, 1, NULL, 0, 0};
			len = recvmsg(fd, &msg, 0);
			if (len <= 0) {
				CSM_DEBUG(PPREFIX "error reading netlink");
				goto fail;
			}

			for (nlh = (struct nlmsghdr *) buf; NLMSG_OK(nlh, len);
			     nlh = NLMSG_NEXT(nlh, len)) {
				/* The end of multipart message. */
				gnlh = nlmsg_data(nlh);
				if (gnlh->cmd == CSM_GENL_DRV_PEER_EVENT) {
					nla = genlmsg_attrdata(gnlh, 0);
					qgennl_process_peer_event(ctx, cmsg,
								    (char *)
								    nla_data(nla),
								    nla_len(nla));
					break;
				} else
					break;
			}
			fail:
			if (cmsg)
				csm_unref_msg(cmsg);
		}
	}

	qgennl_stop(qgennl);

	return NULL;
}

static void qgennl_destroy_link(qgennl_link_t *link)
{
	if (link->sock) {
		nl_socket_free(link->sock);
		link->sock = NULL;
	}
	if (link->send_sock) {
		nl_socket_free(link->send_sock);
		link->send_sock = NULL;
	}

}

static void qgennl_unload(void *ctx)
{
	struct qgennl_ctx *qgennl = (struct qgennl_ctx *)ctx;
	if (qgennl->running) {
		qgennl->running = 0;
		pthread_join(qgennl->thread, NULL);
	}

	qgennl_destroy_link(&qgennl->link);
	free(qgennl);
}

static void qgennl_set_default_config(qgennl_link_t * link)
{
	link->recv_buffer_size = GENLMSG_MAX_SIZE;
}

static int qgennl_open_link(qgennl_link_t * link)
{
	int group_event, group_command;
	int ret;

	link->send_sock = nl_socket_alloc();
	link->sock = nl_socket_alloc();

	if ((NULL == link->send_sock) || (link->sock==NULL)){
		CSM_ERROR("nl alloc sock failed\n");
		return -1;
	}

	nl_socket_disable_seq_check(link->sock);
	nl_socket_disable_seq_check(link->send_sock);

	if (link->recv_buffer_size>0) {
		nl_socket_set_msg_buf_size(link->sock, link->recv_buffer_size);
		CSM_INFO("set size %d\n", link->recv_buffer_size);
	}

	ret = nl_connect(link->sock, NETLINK_GENERIC);
	if(ret) {
		CSM_ERROR("nl connect failed\n");
		return -1;
	}

	ret = nl_connect(link->send_sock, NETLINK_GENERIC);
	if(ret) {
		CSM_ERROR("nl connect failed\n");
		return -1;
	}

	nl_socket_set_nonblocking(link->sock);
	nl_socket_set_nonblocking(link->send_sock);

	group_event =
		genl_ctrl_resolve_grp(link->sock, CSM_FAMILY_NAME, CSM_PEER_EVENT);
	group_command =
		genl_ctrl_resolve_grp(link->sock, CSM_FAMILY_NAME, CSM_APP_COMMAND);

	if (group_event < 0 || group_command < 0) {
		CSM_ERROR("nl resolve group failed\n");
		return -1;
	}

	if(nl_socket_add_memberships(link->sock, group_event, 0) < 0) {
		CSM_ERROR("nl add memberships failed\n");
		return -1;
	}

	if(nl_socket_add_memberships(link->send_sock, group_command, 0) < 0) {
		CSM_ERROR("nl add memberships failed\n");
		return -1;
	}

	link->genl_fam_id =
		genl_ctrl_resolve(link->sock, CSM_FAMILY_NAME);
	if (link->genl_fam_id < 0) {
		CSM_ERROR("gen nl not find family id for %s\n", CSM_FAMILY_NAME);
		return -1;
	}
	return 0;
}

static void *qgennl_load(void *ctx)
{
	int ret;
	qgennl_link_t * link;

	gennl_ctx_t * context = malloc(sizeof(gennl_ctx_t));
	if (context == NULL) {
		CSM_ERROR("cannot create ctx\n");
		goto __fail;
	}

	memset(context, 0, sizeof(gennl_ctx_t));
	context->ctx = ctx;
	link  = &context->link;

	qgennl_set_default_config(link);

	ret = qgennl_open_link(link);

	if (ret) {
		CSM_ERROR("can not open link.\n");
		goto __fail;
	}

	context->running = 1;
	pthread_create(&context->thread, NULL,
			       qgennl_background_thread, context);
	return context;

__fail:
	if (context) {
		qgennl_destroy_link(link);
		free(context);
	}
	return NULL;
}

static struct csm_drv_plugin qgennl_plugin = {
	.plugin_head =
	    INIT_PLUGIN_HEAD(NAME, qgennl_load, qgennl_unload, NULL,
			     NULL),
	.ops = {
		.action = qgennl_action,
		},
};

static struct qgennl_desc g_qgennl_desc = {
	.desc =
	    INIT_PLUGIN_FILE_DESC(CSM_DRIVER_MAGIC, CSM_DRIVER_VERSION, 1),
	.plugin[0] = &qgennl_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *) &g_qgennl_desc;
}
