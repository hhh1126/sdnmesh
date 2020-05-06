/*SH0:
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/
#include "version.h"
#include "csm.h"
#undef __GNUC__
#ifdef Q_OPENWRT
#include "json-c/json.h"
#else
#include "json/json.h"
#endif

#define PPREFIX "[csmd]: "

#ifndef CSM_SUBVERSION
#define CSM_SUBVERSION	"unknown"
#endif

typedef struct _drv_set {
	char *drv;
	struct _drv_set *next;
} drv_set;

typedef struct _comm_set {
	char *comm;
	struct _comm_set *next;
} comm_set;

typedef struct _misc_set {
	char *misc;
	struct _misc_set *next;
} misc_set;

typedef struct _logic_set {
	char *logic;
	struct _logic_set *next;
} logic_set;

typedef struct _csmd_config {
	char *conf_file;
	char *plugins_dir;
	uint8_t mdid[MDID_LEN];
	int max_sta_size;
	int max_bss_size;
	uint32_t daemon:1;
	uint32_t reserve:31;
	drv_set *drv_set;
	comm_set *comm_set;
	misc_set *misc_set;
	logic_set *logic_set;
} csmd_config;


static csmd_config g_config = {
	.plugins_dir = NULL,
	.logic_set = NULL,
	.drv_set = NULL,
	.misc_set = NULL,
	.mdid = {0},
	.max_sta_size = 1024,
	.max_bss_size = 0,
	.conf_file = "csmd.conf",
	.daemon = 0,
};

static char *g_plugin_dir[] = {
	"logic",
	"driver",
	"comm",
	"misc"
};

static uint32_t g_plugin_version[] = {
	CSM_LOGIC_VERSION,
	CSM_DRIVER_VERSION,
	CSM_COMM_VERSION,
	CSM_MISC_VERSION
};

static uint32_t g_plugin_magic[] = {
	CSM_LOGIC_MAGIC,
	CSM_DRIVER_MAGIC,
	CSM_COMM_MAGIC,
	CSM_MISC_MAGIC
};

static void signal_handler(int sig)
{
	exit(0);
}


static void mdid_get_from_string(uint8_t * mdid, const char *str)
{
	int buf[MDID_LEN];
	if (sscanf(str, "%02x:%02x", &buf[0], &buf[1])) {
		mdid[0] = (uint8_t) buf[0];
		mdid[1] = (uint8_t) buf[1];
	}
}

static int csmd_add_driver(const char *name)
{
	drv_set *dset = CSM_MALLOC(sizeof(drv_set));
	if (dset) {
		dset->drv = strdup(name);
		dset->next = g_config.drv_set;
		g_config.drv_set = dset;
	}
	return 0;
}

#if 0
static int csmd_add_comm(const char *name)
{
	comm_set *cset = CSM_MALLOC(sizeof(comm_set));
	if (cset) {
		cset->comm = strdup(name);
		cset->next = g_config.comm_set;
		g_config.comm_set = cset;
	}
	return 0;
}

static int csmd_add_misc(const char *name)
{
	misc_set *cset = CSM_MALLOC(sizeof(misc_set));
	if (cset) {
		cset->misc = strdup(name);
		cset->next = g_config.misc_set;
		g_config.misc_set = cset;
	}
	return 0;
}
#endif

static int csmd_add_logic(const char *name)
{
	logic_set *lset = CSM_MALLOC(sizeof(logic_set));
	if (lset) {
		lset->logic = strdup(name);
		lset->next = g_config.logic_set;
		g_config.logic_set = lset;
	}
	return 0;
}

static int csmd_add_mdid(const char *value)
{
	if (memcmp(g_config.mdid, default_mdid, MDID_LEN))
		return -2;
	else
		mdid_get_from_string(g_config.mdid, value);
	return 0;
}

static int csmd_add_conf_file(const char *name)
{
	if (name) {
		g_config.conf_file = strdup(name);
		return 0;
	}
	return 0;
}

#if 0
static int csm_init_handler(void *user, const char *section,
			    const char *name, const char *value)
{
	if (MATCH(section, "csmd")) {
		if (MATCH(name, "driver"))
			return csmd_add_driver(value);
		else if (MATCH(name, "communication"))
			return csmd_add_comm(value);
		else if (MATCH(name, "misc"))
			return csmd_add_misc(value);
		else if (MATCH(name, "logic"))
			return csmd_add_logic(value);
		else if (MATCH(name, "mdid"))
			return csmd_add_mdid(value);
		else if (MATCH(name, "debug_level"))
			CSM_SET_DEBUG_LEVEL(value);
		else if (MATCH(name, "debug_output"))
			csm_log_set_output(value);
	}
	return 0;

}
#endif

static void print_help()
{

}

static int csm_parse_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:l:e:m:c:p:D")) != -1) {
		switch (c) {
		case 'd':
			csmd_add_driver(optarg);
			break;
		case 'l':
			csmd_add_logic(optarg);
			break;
		case 'm':
			csmd_add_mdid(optarg);
			break;
		case 'c':
			csmd_add_conf_file(optarg);
			break;
		case 'p':
			g_config.plugins_dir = optarg;
			break;
		case 'D':
			g_config.daemon = 1;
			break;
		default:
			print_help();
		}
	}
	return 0;
}

/* nochdir = 0, and noclose = 1 */
static int csm_daemonize()
{
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		return 0;
	default:
		_exit(0);
	}

	if (setsid() == -1)
		return -1;
	chdir("/");
}

static char *csm_get_plugins_dir_name(int type)
{
	char *name = NULL, *base;
	char *dirname = g_plugin_dir[type];

	if (g_config.plugins_dir)
		base = strdup(g_config.plugins_dir);
	else
		base = "/usr/lib";
	asprintf(&name, "%s/%s", base, dirname);
	return name;
}

static DIR *csm_get_plugins_dir(char *dirname)
{
	DIR *dir = opendir(dirname);
	return dir;
}

static commctx_t *get_default_comm(csmctx_t * ctx)
{
	return (commctx_t *) ctx->comms;
}

static int register_comm_logic_callbacks(csmctx_t * ctx,
					 commctx_t * comm_ctx)
{
	mobility_domain_t *md = (mobility_domain_t *) ctx->mds;
	struct csm_comm_ops *comm = &comm_ctx->comm.plugin.cplugin->ops;

	while (md) {
		int i;
		for (i = 0; i < LOGIC_ROLE_MAX; i++) {
			if (md->instance_mask & (1 << i)) {
				struct csm_logic_instance_ops *sl =
				    &md->logic[i].plugin.splugin->ops;

				if (md->logic[i].plugin.splugin->type
					!= LOGIC_ROLE_STEERING)
					continue;

				if (comm->register_clbks)
					comm->register_clbks
					    (sl->connect_complete,
					     sl->bss_trans_status,
					     sl->tables_sync,
					     sl->recv_rpe);
				if (sl->register_clbks)
					sl->register_clbks(comm->get_role,
							   comm->connect_complete,
							   comm->notify_bss_status,
							   comm->notify_deauth,
							   comm->deauth,
							   comm->bss_trans_req,
							   comm->bss_trans_status,
							   comm->tables_sync,
							   comm->send_rpe);
			}
		}
		md = md->next;
	}
	return 0;
}

static int register_logic_comm_clbks(csmctx_t * ctx)
{
	commctx_t *commctx = get_default_comm(ctx);

	if (commctx) {
		return register_comm_logic_callbacks(ctx, commctx);
	} else {
		return 0;
	}
}

static int csm_scheduler()
{
	while (1) {
		sleep(10);
	};
	return 0;
}

#if 0
static void csm_print_usage()
{
	printf("(csmd %s-%s) Usage: csmd \n", CSM_VERSION, CSM_SUBVERSION);
}
#endif

static void *csm_load_single_plugins(int type)
{
	char *plugin_dir_name = NULL;
	DIR *plugin_dir = NULL;
	void *plugin = NULL;
	uint32_t version = g_plugin_version[type];
	uint32_t magic = g_plugin_magic[type];
	if (((plugin_dir_name = csm_get_plugins_dir_name(type)))
	    && ((plugin_dir = csm_get_plugins_dir(plugin_dir_name)))) {
		plugin =
		    csm_load_plugins(plugin_dir, plugin_dir_name, version,
				     magic);
	}
	if (plugin_dir_name)
		CSM_FREE(plugin_dir_name);
	if (plugin_dir)
		closedir(plugin_dir);

	return plugin;
}

#if 0
static void csmd_generate_set_cmd_buffer(char *buf, const char *key,
					 const char *value)
{
	*(buf++) = 4;
	buf += sprintf(buf, "csmd");
	*(buf++) = '\0';
	buf += sprintf(buf, "set");
	*(buf++) = '\0';
	buf += sprintf(buf, "%s", key);
	*(buf++) = '\0';
	buf += sprintf(buf, "%s", value);
	*(buf++) = '\0';
}

static int csmd_set_json_plugin_parameters(struct plugin_instance
					   *pinstance,
					   struct json_object *jparameters)
{
	char req[1024];
	char rep[1024];
	if (pinstance->plugin.plugin_head->ops.control) {
		json_object_object_foreach(jparameters, key, obj) {
			const char *value = json_object_get_string(obj);
			if (value) {
				csmd_generate_set_cmd_buffer(req, key,
							     value);
				pinstance->plugin.plugin_head->
				    ops.control(pinstance->instance, req,
						rep, sizeof(rep));
			}
		}

	}
	return 0;
}
#endif

static int csmd_parse_json_networks(csmctx_t * csm,
				    struct json_object *jnetworks)
{
	int i = 0;
	struct json_object *jnetwork;

	while ((jnetwork =
		json_object_array_get_idx(jnetworks, i)) != NULL) {
		struct json_object *jmdid;
		uint8_t mdid[MDID_LEN] = { 0, 0 };
		if ((jmdid = json_object_object_get(jnetwork, "MDID"))) {
			struct json_object *jlogics;
			mdid_get_from_string(mdid, json_object_get_string(jmdid));
			if ((jlogics =
			     json_object_object_get(jnetwork, "logics"))) {
				struct json_object *jlogic, *jparams;
				int j = 0;
				while ((jlogic =
					json_object_array_get_idx(jlogics,
								  j))) {
					struct json_object *jlogic_name;
					if ((jlogic_name =
					     json_object_object_get(jlogic,
								    "name")))
					{
						jparams =
						    json_object_object_get
						    (jlogic, "parameters");

						csm_attach_logic_to_mobility_domain
						    (csm,
						     json_object_get_string
						     (jlogic_name), mdid,
						     jparams);
					}
					j++;
				}
			}
		}
		i++;
	}
	return 0;
}

static int csmd_parse_json_drivers(csmctx_t * ctx,
				   struct json_object *jdrivers)
{
#if 0
	int i = 0;
	struct json_object *jdriver;
	while ((jdriver = json_object_array_get_idx(jdrivers, i)) != NULL) {
		struct json_object *jdriver_name, *jparams;
		if ((jdriver_name =
		     json_object_object_get(jdriver, "name"))) {
			jparams =
			    json_object_object_get(jdriver, "parameters");
			csm_attach_drv(ctx,
				       json_object_get_string
				       (jdriver_name), jparams);
		}
		i++;
	}
#else
	/* dummy parse from csmd.json, always attach all plugins that driver support */
	struct csm_plugin *plugin;
	plugin = (struct csm_plugin *) (ctx->drv_plugins);

	while (plugin) {
		csm_attach_drv(ctx, (const char *) plugin->plugin_name, NULL);
		plugin = plugin->next;
	}

#endif
	return 0;
}

static int csmd_parse_json_comms(csmctx_t * ctx,
				 struct json_object *jcomms)
{
	int i = 0;
	struct json_object *jcomm;
	while ((jcomm = json_object_array_get_idx(jcomms, i)) != NULL) {
		struct json_object *jcomm_name, *jparams;
		if ((jcomm_name = json_object_object_get(jcomm, "name"))) {
			jparams =
			    json_object_object_get(jcomm, "parameters");
			csm_attach_comm(ctx,
					json_object_get_string
					(jcomm_name), jparams);
		}
		i++;
	}
	return 0;
}

static int csmd_parse_json_miscs(csmctx_t * ctx,
				 struct json_object *jmiscs)
{
	int i = 0;
	struct json_object *jmisc;
	while ((jmisc = json_object_array_get_idx(jmiscs, i)) != NULL) {
		struct json_object *jmisc_name, *jparams;
		if ((jmisc_name = json_object_object_get(jmisc, "name"))) {
			jparams =
			    json_object_object_get(jmisc, "parameters");
			csm_attach_misc(ctx,
					json_object_get_string
					(jmisc_name), jparams);

		}
		i++;
	}
	return 0;
}

static int csmd_parse_json_logging(csmctx_t * ctx,
				   struct json_object *jlogging)
{
	struct json_object *jlevel, *joutput;
	const char *level = NULL, *output = NULL;
	if ((jlevel = json_object_object_get(jlogging, "level")))
		level = json_object_get_string(jlevel);
	if ((joutput = json_object_object_get(jlogging, "output")))
		output = json_object_get_string(joutput);

	CSM_SET_DEBUG_LEVEL(level);
	csm_log_set_output(output);
	return 0;
}

static int csmd_parse_json_parameters(csmctx_t * ctx,
				   struct json_object *jparams)
{
	struct json_object *jobj;

	if ((jobj = json_object_object_get(jparams, "phyrate_avg_age")))
		ctx->params.phyrate_avg_age = json_object_get_int(jobj);
	if ((jobj = json_object_object_get(jparams, "rssi_avg_age")))
		ctx->params.rssi_avg_age = json_object_get_int(jobj);
	if ((jobj = json_object_object_get(jparams, "statsdump_lines_perfile")))
		ctx->params.statsdump_lines_perfile = json_object_get_int(jobj);
	if ((jobj = json_object_object_get(jparams, "statsdump_files")))
		ctx->params.statsdump_files = json_object_get_int(jobj);
	return 0;
}

static int csmd_parse_json_database(csmctx_t * ctx,
				    struct json_object *jconfig)
{
	struct json_object *jmax_size, *jstale, *jdatabase;
	if ((jdatabase = json_object_object_get(jconfig, "database"))) {
		if ((jmax_size = json_object_object_get(jdatabase, "max_stadb_size")))
			g_config.max_sta_size = json_object_get_int(jmax_size);
		if ((jstale = json_object_object_get(jdatabase, "sta_ageout")))
			ctx->sta_ageout_config.age_timeout = json_object_get_int(jstale);
	}
	return 0;
}

static int csmd_pre_parse_json_config(csmctx_t * ctx,
				      struct json_object *jconfig)
{
	return csmd_parse_json_database(ctx, jconfig);
}

static int csmd_parse_json_config(csmctx_t * ctx,
				  struct json_object *jconfig)
{
	int ret = 0;

	json_object_object_foreach(jconfig, key, obj) {
		if (MATCH(key, "networks")) {
			csmd_parse_json_networks(ctx, obj);
		} else if (MATCH(key, "communications")) {
			csmd_parse_json_comms(ctx, obj);
		} else if (MATCH(key, "miscs")) {
			csmd_parse_json_miscs(ctx, obj);
		} else if (MATCH(key, "logging")) {
			csmd_parse_json_logging(ctx, obj);
		} else if (MATCH(key, "parameters")) {
			csmd_parse_json_parameters(ctx, obj);
		}
	}

	return ret;
}

static void csmd_parse_driver_json_config(csmctx_t *ctx,
	struct json_object *jconfig)
{
	json_object_object_foreach(jconfig, key, obj) {
		if (MATCH(key, "drivers"))
			csmd_parse_json_drivers(ctx, obj);
	}
}

static void csmd_init_params(csmctx_t *csm)
{
	csm->params.phyrate_avg_age = 30;
	csm->params.rssi_avg_age = 30;
	csm->params.statsdump_lines_perfile = 5000;
	csm->params.statsdump_files = 2;
}

int main(int argc, char *argv[])
{
	int ret = -1;

	csmctx_t *csm = NULL;
	struct json_object *jconfig;

	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	if (csm_parse_args(argc, argv)) {
		goto bail;
	}

	jconfig = json_object_from_file(g_config.conf_file);
	if (jconfig == NULL) {
		printf("Can't load '%s'\n", g_config.conf_file);
		goto bail;
	}

	if (((csm = csm_init())) == NULL)
		goto bail;

	printf(PPREFIX "(%s-%s) started(%p)\n", CSM_VERSION, CSM_SUBVERSION, csm);

	if (g_config.daemon && csm_daemonize())
		printf(PPREFIX "daemonize failed!");

	csmd_pre_parse_json_config(csm, jconfig);

	if (((csm->logic_plugins =
	      csm_load_single_plugins(CSM_PLUGIN_TYPE_LOGIC)) == NULL))
		goto bail;
	if (((csm->drv_plugins =
	      csm_load_single_plugins(CSM_PLUGIN_TYPE_DRIVER)) == NULL))
		goto bail;
	csm->comm_plugins = csm_load_single_plugins(CSM_PLUGIN_TYPE_COMM);
	csm->misc_plugins = csm_load_single_plugins(CSM_PLUGIN_TYPE_MISC);

	ret = csm_create_radio_db(csm, 0);
	if (ret)
		goto bail;
	ret = csm_create_bss_db(csm, g_config.max_bss_size);
	if (ret)
		goto bail;
	ret = csm_create_station_db(csm, g_config.max_sta_size);
	if (ret)
		goto bail;

	csmd_init_params(csm);
	if (csmd_parse_json_config(csm, jconfig)) {
		goto bail;
	}
	register_logic_comm_clbks(csm);

	/* attach/start the driver after all others */
	csmd_parse_driver_json_config(csm, jconfig);

	csm_scheduler();

	if (csm->stats_dump.file)
		fclose(csm->stats_dump.file);

      bail:
	if (csm) {
		CSM_FREE(csm);
	}
	printf(PPREFIX "terminated\n");
	closelog();

	return 0;
}
