/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSM_PLUGIN_H_
#define _CSM_PLUGIN_H_

#include <sys/types.h>
#include <dirent.h>

#define LOAD_PLUGIN(oneplugin, ctx) ((csm_plugin_head *)(oneplugin))->ops.create((ctx))
#define UNLOAD_PLUGIN(oneplugin, ctx) ((csm_plugin_head *)(oneplugin))->ops.destroy((ctx))

#define INIT_PLUGIN_HEAD(plugin_name, create_func, destroy_func, get_parameter_func, set_parameter_func) \
	{\
	.name = (plugin_name),\
	.ops = {\
		.create = (create_func),\
		.destroy = (destroy_func),\
		.get_parameter = (get_parameter_func),\
		.set_parameter = (set_parameter_func),\
		.control = NULL\
	}\
	}
#define INIT_PLUGIN_HEAD_1(plugin_name, create_func, destroy_func, get_parameter_func, set_parameter_func, control_func) \
	{\
	.name = (plugin_name),\
	.ops = {\
		.create = (create_func),\
		.destroy = (destroy_func),\
		.get_parameter = (get_parameter_func),\
		.set_parameter = (set_parameter_func),\
		.control = (csm_plugin_control_func)(control_func)\
	}\
	}

#define INIT_PLUGIN_FILE_DESC(file_magic, file_version, pluginnum) \
	{\
	.magic = (file_magic),\
	.version = (file_version),\
	.plugin_num = (pluginnum),\
	}

enum {
	CSM_PLUGIN_TYPE_LOGIC = 0,
	CSM_PLUGIN_TYPE_DRIVER,
	CSM_PLUGIN_TYPE_COMM,
	CSM_PLUGIN_TYPE_MISC,
};

struct csm_plugin {
	char *file_name;
	char *plugin_name;
	void *plugin;
	struct csm_plugin *next;
};
typedef int (*csm_plugin_control_func) (void *, char *, char *, int);

typedef struct {
	void *(*create) (void *);
	void (*destroy) (void *);
	int (*get_parameter) (char *, char *);
	int (*set_parameter) (char *, char *);
	int (*control) (void *, char *, char *, int);
} csm_plugin_ops;

typedef struct {
	char *name;
	csm_plugin_ops ops;
} csm_plugin_head;

struct csm_plugin_file_desc {
	uint32_t magic;
	int32_t version;
	uint32_t plugin_num;
	csm_plugin_head *plugin[0];
};

struct plugin_instance {
	void *instance;
	union {
		csm_plugin_head *plugin_head;
		struct csm_logic_plugin *splugin;
		struct csm_drv_plugin *dplugin;
		struct csm_comm_plugin *cplugin;
		struct csm_misc_plugin *mplugin;
	} plugin;
};




void *csm_load_plugins(DIR * dir, char *dirname, uint32_t version,
		       uint32_t magic);

csm_plugin_head *csm_find_plugin(void *plugins, const char *name);

#define CSM_ROLE_TYPE_MASK	0x0000000f
enum {
	CSM_ROLE_UNCONFIGURED = 0,
	CSM_ROLE_MASTER,
	CSM_ROLE_SLAVE,
};
#define CSM_ROLE_INACTIVE	0x80000000

typedef struct csm_plugin_file_desc *(*csm_plugin_file_entry_func) (void);
typedef int (*qsteer_get_role_t) (void);
typedef int (*qsteer_connect_complete_t) (uint8_t * mdid, uint8_t * bss, uint8_t * sta);
typedef int (*qsteer_notify_bss_status_t) (uint8_t * bss, uint32_t status);
typedef int (*qsteer_notify_deauth_t) (uint8_t * bss, uint8_t * sta);
typedef int (*qsteer_deauth_t) (uint8_t * bss, uint8_t * sta,
				uint16_t code, int blacklist);
typedef int (*qsteer_bss_trans_req_t) (uint8_t * bss, uint8_t * payload, uint32_t len);
typedef int (*qsteer_bss_trans_status_t) (uint8_t * mdid, uint8_t * sta,
					  uint8_t status);
#define CSM_TABLES_SYNC_CODE_START	((uint8_t)0)
#define CSM_TABLES_SYNC_CODE_DONE	((uint8_t)1)
typedef int (*qsteer_tables_sync_t) (uint8_t code, void *uctx);
typedef int (*qsteer_send_rpe_t) (uint8_t *bss, uint8_t *rpe, uint32_t len);
typedef int (*qsteer_recv_rpe_t) (uint8_t *bss, uint8_t *rpe, uint32_t len);

struct csm_qsteer_nsteer {
#define CSM_QSTEER_NSTEER_ADD	0
#define CSM_QSTEER_NSTEER_DEL	1
	uint8_t op;
	uint8_t mac[ETH_ALEN];
};

struct csm_qsteer_control {
#define CSM_QSTEER_CTL_ID_NSTEER	0
	uint32_t id;
	union {
		struct csm_qsteer_nsteer nsteer;
	} u;
};
typedef int (*qsteer_control_t) (uint8_t *mdid, struct csm_qsteer_control *ctrl);


#define CSM_PLUGIN_FILE_ENTRY_NAME "csm_plugin_get_desc"

#define CSM_LOGIC_VERSION 1
#define CSM_LOGIC_MAGIC (0x4c4f4749)
enum {
	LOGIC_ROLE_STEERING = 0,
	LOGIC_ROLE_SPDIA,
	LOGIC_ROLE_MAX
};

enum {
	CSM_LOGIC_IEVENT_HESSID_UPDATE = 0
};

struct csm_logic_instance_ops {
	int (*recv_event) (void *ctx, csmmsg_t * event);
	void (*notify_ievent) (void *ctx, uint32_t event, void *param);
	qsteer_connect_complete_t connect_complete;
	qsteer_bss_trans_status_t bss_trans_status;
	qsteer_tables_sync_t tables_sync;
	qsteer_recv_rpe_t recv_rpe;
	qsteer_control_t control;
	int (*register_clbks) (qsteer_get_role_t comm_get_role,
			       qsteer_connect_complete_t
			       comm_connect_complete,
			       qsteer_notify_bss_status_t comm_notify_bss_status,
			       qsteer_notify_deauth_t comm_notify_deauth,
			       qsteer_deauth_t comm_deauth,
			       qsteer_bss_trans_req_t comm_bss_trans_req,
			       qsteer_bss_trans_status_t
			       comm_bss_trans_status,
			       qsteer_tables_sync_t
			       comm_tables_sync,
			       qsteer_send_rpe_t
			       comm_send_rpe);
};

struct csm_logic_plugin {
	csm_plugin_head plugin_head;
	int type;
	struct csm_logic_instance_ops ops;
};
#define CSM_DRIVER_VERSION 1
#define CSM_DRIVER_MAGIC (0x44524956)
struct csm_drv_ops {
	int (*action) (void *ctx, csmmsg_t * action);
};

struct csm_drv_plugin {
	csm_plugin_head plugin_head;
	struct csm_drv_ops ops;
};

#define CSM_COMM_VERSION 1
#define CSM_COMM_MAGIC (0x434f4d4d)
struct csm_comm_ops {
	int (*action) (void *ctx, void *action);
	qsteer_get_role_t get_role;
	qsteer_connect_complete_t connect_complete;
	qsteer_notify_bss_status_t notify_bss_status;
	qsteer_notify_deauth_t notify_deauth;
	qsteer_deauth_t deauth;
	qsteer_bss_trans_req_t bss_trans_req;
	qsteer_bss_trans_status_t bss_trans_status;
	qsteer_tables_sync_t tables_sync;
	qsteer_send_rpe_t send_rpe;
	int (*register_clbks) (qsteer_connect_complete_t
			       sl_connect_complete,
			       qsteer_bss_trans_status_t
			       sl_bss_trans_status,
			       qsteer_tables_sync_t
			       sl_tables_sync,
			       qsteer_recv_rpe_t
			       recv_rpe);
};

struct csm_comm_plugin {
	csm_plugin_head plugin_head;
	struct csm_comm_ops ops;
};

#define CSM_MISC_VERSION 1
#define CSM_MISC_MAGIC (0x4d495343)

struct csm_misc_plugin {
	csm_plugin_head plugin_head;
};


#endif
