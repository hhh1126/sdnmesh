/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          		 **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include "spdia_qtn.h"
#include "spdia_dbg.h"
#include "spdia_cli.h"

typedef enum {
	T_UINT32 = 0,
} spdia_param_type_e;

struct spdia_param {
	const char *name;
	spdia_param_type_e type;
	int offset;
	int min_val;
	int max_val;
};

static int spdia_print_config_usage(char *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage: %s diag add <mac> [key=val]\n"
		"	period=val			: set the CSI monitoring period in ms\n"
		"	mode=<mixed/data/ndp/none>	: set the CSI monitoring operation mode\n"
		"	reorder=<0/1>			: enable/disable CSI tone reordering\n"
		"	ng=<0/1/2>			: set the CSI decimation control\n", basename(cli)
	);
}

static int spdia_print_ctrl_usage(char *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage: %s <command> [<parameter>] [<value>]\n"
		"Commands:\n"
		"	set <param> <value>			: set the run-time param\n"
		"	get [<param>]				: get the run-time param\n"
		"  	diag show				: show all diagnoised sta\n"
		"  	diag add <mac> [key=val]		: add and config a sta to diagnoise\n"
		"  	diag del <mac>			 	: del the given sta from diagnoised list\n"
		"	dbg level/stdout <level>                : set dbg level\n", basename(cli)
	);
}

#define SPDIA_PARAM_ITEM(_param, _type)	_type, offsetof(spdia_cfg_t, _param)
static const struct spdia_param g_params[] = {
#ifdef SPDIA_SUPPORT_FILE_DUMP
	{"dump_level", SPDIA_PARAM_ITEM(dump_level, T_UINT32), 0, 3},
	{"dump_interval", SPDIA_PARAM_ITEM(dump_interval, T_UINT32), 0, 10000},
	{"dump_burst", SPDIA_PARAM_ITEM(dump_burst, T_UINT32), 0, 0x7fffffff},
	{"dump_kbytes", SPDIA_PARAM_ITEM(dump_kbytes, T_UINT32), 1, 1000000},
#endif
#ifdef SPDIA_SUPPORT_TCP_DUMP
	{"dump_port", SPDIA_PARAM_ITEM(dump_port, T_UINT32), 1024, 65535},
#endif
};
#define SPDIA_PARAM_ITEMS	(sizeof(g_params) / sizeof(struct spdia_param))

static int spdia_print_param_value(const struct spdia_param *param,
	char *rep, int rep_len)
{
	uint8_t *var = ((uint8_t *)(&g_ctx.cfg)) + param->offset;
	int len = 0;

	switch (param->type) {
	case T_UINT32:
		len = snprintf(rep, rep_len, "%u\n", *((uint32_t *)var));
		break;

	default:
		break;
	}

	return len;
}

static int spdia_print_all_params_value(char *rep, int rep_len)
{
	int i;
	char *pos, *end;
	const struct spdia_param *param = &g_params[0];

	pos = rep;
	end = rep + rep_len;

	for (i = 0; i < SPDIA_PARAM_ITEMS; ++i, ++param) {
		pos += snprintf(pos, end - pos, "%s ", param->name);
		if (pos >= end)
			goto _out;
		pos += spdia_print_param_value(param, pos, end - pos);
		if (pos >= end)
			goto _out;
	}

_out:
	return pos - rep;
}

static int spdia_set_param_value(const char *name,
	const char *value, char *rep, int rep_len)
{
	const struct spdia_param *param = &g_params[0];
	uint8_t *var;
	const char *p;
	int i;

	for (i = 0; i < SPDIA_PARAM_ITEMS; ++i, ++param)
		if (strcmp(param->name, name) == 0)
			break;

	if (i >= SPDIA_PARAM_ITEMS)
		return snprintf(rep, rep_len, "Don't support parameter %s\n", name);

	var = ((uint8_t *)(&g_ctx.cfg)) + param->offset;

	if (param->type == T_UINT32) {
		for (p = value; (*p >= '0' && *p <= '9'); ++p)
			;
		if (*p != '\0'
			|| (value[0] == '0' && value[1] != '\0')) /* treat "0" as valid and '01' as invalid */
			return snprintf(rep, rep_len,
				"value[%s] of %s must be decimal digit\n", value, name);
		i = atoi(value);
		if (i < param->min_val || i > param->max_val)
			return snprintf(rep, rep_len, "value[%s] of %s must be in %d ~ %d\n",
				value, name, param->min_val, param->max_val);
		*((uint32_t *)var) = (uint32_t)i;
	}

	return snprintf(rep, rep_len, "success\n");
}

static int spdia_print_diagnosed_sta(char *rep, int rep_len)
{
	spdia_sta_cfg_t *sta = NULL;
	char *pos, *end;

	pos = rep;
	end = rep + rep_len;

	pthread_mutex_lock(&g_ctx.sta_mutex);
	if (list_empty(&g_ctx.sta_head)) {
		pos += snprintf(pos, end - pos, "diagnosed STA is null\n");
	} else {
		list_for_each_entry(sta, &g_ctx.sta_head, lh) {
			pos += snprintf(pos, end - pos, SPDIA_MACFMT ": period %u\n",
				SPDIA_MACARG(sta->mac), sta->period);

			if(pos >= end)
				break;
		}
	}
	pthread_mutex_unlock(&g_ctx.sta_mutex);

	return pos - rep;
}

static int spdia_del_diagnosed_sta(const char *mac_str)
{
	spdia_sta_cfg_t *sta, *tmp;
	struct ether_addr macaddr;
	uint8_t del_all = 0;

	if (!strcmp(mac_str, "all"))
		del_all = 1;
	else if (ether_aton_r(mac_str, &macaddr) == NULL) {
		SPDIA_ERROR("%s must be hex-digits-and-colons notation unicast MAC address\n",
			mac_str);
		return -1;
	}

	pthread_mutex_lock(&g_ctx.sta_mutex);
	list_for_each_entry_safe(sta, tmp, &g_ctx.sta_head, lh) {
		if(del_all
			|| SPDIA_MAC_EQ(sta->mac, macaddr.ether_addr_octet)) {
			list_del(&sta->lh);
			spdia_update_diagnosed_sta(sta->mac, 0, 0, 0, 0, 0);
			SPDIA_FREE(sta);

			if(!del_all)
				break;
		}
	}
	pthread_mutex_unlock(&g_ctx.sta_mutex);

	return 0;
}

static int spdia_add_diagnosed_sta(const char *mac_str, int period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth)
{
	struct ether_addr macaddr;
	spdia_sta_cfg_t *sta = NULL;
	int found = 0;

	if (ether_aton_r(mac_str, &macaddr) == NULL) {
		SPDIA_ERROR("%s must be hex-digits-and-colons notation unicast MAC address\n",
			mac_str);
		return -1;
	}

	pthread_mutex_lock(&g_ctx.sta_mutex);
	list_for_each_entry(sta, &g_ctx.sta_head, lh) {
		if (SPDIA_MAC_EQ(sta->mac, macaddr.ether_addr_octet)) {
			sta->period = period;
			sta->reorder = reorder;
			sta->mode = mode;
			sta->ng = ng;
			sta->smooth = smooth;
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&g_ctx.sta_mutex);

	if (found && sta) {
		spdia_update_diagnosed_sta(sta->mac, sta->period,
			sta->reorder, sta->mode, sta->ng, sta->smooth);
		return 0;
	}

	sta = SPDIA_CALLOC(1, sizeof(spdia_sta_cfg_t));
	if(NULL == sta)
		return -2;
	SPDIA_MAC_COPY(sta->mac, macaddr.ether_addr_octet);
	sta->period = period;
	sta->reorder = reorder;
	sta->mode = mode;
	sta->ng = ng;
	sta->smooth = smooth;

	spdia_update_diagnosed_sta(sta->mac, sta->period,
		sta->reorder, sta->mode, sta->ng, sta->smooth);

	pthread_mutex_lock(&g_ctx.sta_mutex);
	list_add_tail(&sta->lh, &g_ctx.sta_head);
	pthread_mutex_unlock(&g_ctx.sta_mutex);

	return 0;
}

int spdia_parse_diag_sta_config(char **argv, int argc, uint16_t *parse_period,
	uint8_t *parse_reorder, uint8_t *parse_mode_data, uint8_t *parse_mode_ndp,
	uint8_t *parse_ng, uint8_t *parse_smooth)
{
	int offset = 4;
	char *key, *value;

	while (argc > offset) {
		key = argv[offset];
		value = strchr(key, '=');
		if (!value) {
			offset++;
			continue;
		}
		*value++ = '\0';

		if (strncmp(key, "period",6) == 0)
			*parse_period = atoi(value);
		else if (strncmp(key, "mode",4) == 0) {
			if (strncmp(value, "data", 4) == 0) {
				*parse_mode_data = 1;
				*parse_mode_ndp = 0;
			} else if (strncmp(value, "ndp", 3) == 0) {
				*parse_mode_data = 0;
				*parse_mode_ndp = 1;
			} else if (strncmp(value, "none", 4) == 0) {
				*parse_mode_data = 0;
				*parse_mode_ndp = 0;
			} else if (strncmp(value, "mixed", 5) == 0) {
				*parse_mode_data = 1;
				*parse_mode_ndp = 1;
			}
		} else if (strncmp(key, "reorder", 7) == 0) {
			*parse_reorder = atoi(value);
		} else if (strncmp(key, "ng", 2) == 0) {
			*parse_ng = atoi(value);
		} else if (strncmp(key, "smooth", 6) == 0) {
			*parse_smooth = atoi(value);
		} else {
			SPDIA_WARN("The key %s is not allowed in spdia cli parsing\n", key);
		}

		offset++;
	}

	return 0;
}

void spdia_load_cfg(void)
{
	spdia_cfg_t *cfg = &g_ctx.cfg;

	const struct spdia_param *param = &g_params[0];
	char *var;
	int ret, i, type;
	csm_param_value value;

	for (i = 0; i < SPDIA_PARAM_ITEMS; ++i, ++param) {
		type = param->type;
		var = ((char *)cfg) + param->offset;
		ret = csm_param_get_value(g_ctx.ctx, &value, param->name, CSM_PARAM_INT, -1);
		if (ret != 0)
			continue;

		if (value.int_value < param->min_val || value.int_value > param->max_val) {
			SPDIA_WARN("invalid value for parameter %s, it must be in %d ~ %d\n",
				param->name, param->min_val, param->max_val);
			continue;
		}
		switch (type) {
		case T_UINT32:
			*((uint32_t *)var) = value.int_value;
			break;
		default:
			break;
		}
	}

	if (csm_param_get_value(g_ctx.ctx, &value,
		"log_level", CSM_PARAM_STRING, -1) == 0) {
		int level;
		if ((level = csm_level_no(value.str_value)) >= 0)
			SPDIA_SET_LOG_LEVEL(value.str_value);
	}

	i = 0;
	while (csm_param_get_value(g_ctx.ctx,
		&value, "stations", CSM_PARAM_OBJECT, i++) == 0) {
		csm_param_value mac, period, reorder, mode, ng, smooth;
		uint8_t mode_data = 1, mode_ndp = 0, op_mode;
		if (csm_object_param_get_value(g_ctx.ctx,
				value.object, &mac, "mac", CSM_PARAM_STRING, -1)
			|| csm_object_param_get_value(g_ctx.ctx,
				value.object, &period, "period", CSM_PARAM_INT, -1)) {
			SPDIA_WARN("skip %uth diagnosed station: parsed failed\n", i);
			continue;
		}

		if (csm_object_param_get_value(g_ctx.ctx, value.object,
				 &reorder, "reorder", CSM_PARAM_INT, -1) != 0)
				 reorder.int_value = 1;

		if (csm_object_param_get_value(g_ctx.ctx,
				value.object, &mode, "mode", CSM_PARAM_STRING, -1) == 0) {
			if (strncmp(mode.str_value, "data", 4) == 0) {
				mode_data = 1;
				mode_ndp = 0;
			} else if (strncmp(mode.str_value, "ndp", 3) == 0) {
				mode_data = 0;
				mode_ndp = 1;
			} else if (strncmp(mode.str_value, "none", 4) == 0) {
				mode_data = 0;
				mode_ndp = 0;
			} else if (strncmp(mode.str_value, "mixed", 5) == 0) {
				mode_data = 1;
				mode_ndp = 1;
			} else {
				SPDIA_WARN("the mode setting of station %s of is unrecognizable %s\n",
						mac.str_value, mode.str_value);
			}
		}

		if (csm_object_param_get_value(g_ctx.ctx, value.object,
				 &ng, "ng", CSM_PARAM_INT, -1) != 0)
			ng.int_value = 1;

		if (csm_object_param_get_value(g_ctx.ctx, value.object,
				 &smooth, "smooth", CSM_PARAM_INT, -1) != 0)
			smooth.int_value = 0;

		op_mode = (mode_data << SPDIA_MODE_DATA_SHIFT) |
                                (mode_ndp << SPDIA_MODE_NDP_SHIFT);
		spdia_add_diagnosed_sta(mac.str_value, period.int_value,
			reorder.int_value, op_mode, ng.int_value, smooth.int_value);
	}
}

static int spdia_ctrl_handle_req(char *req, int req_len, char *rep, int rep_len)
{
	int argc, i;
	char *argv[256] = { NULL };
	char *pos, *end;
	const struct spdia_param *param = &g_params[0];

	argc = req[0];

	pos = &req[1];
	for (i = 0; i < argc && pos < req + req_len; ++i, ++pos) {
		argv[i] = pos;
		while(*pos)
			++pos;
	}

	if (argc <= 1)
		return spdia_print_ctrl_usage(argv[0], rep, rep_len);

	pos = rep;
	end = rep + rep_len;
	if (strcmp("get", argv[1]) == 0) {
		if(argc <= 2) {
			pos += spdia_print_all_params_value(pos, end - pos);
			if (pos >= end)
				goto __out;
		} else {
			for (i = 0; i < SPDIA_PARAM_ITEMS; ++i, ++param)
				if (strcmp(param->name, argv[2]) == 0)
					break;
			if (i >= SPDIA_PARAM_ITEMS)
				pos += snprintf(rep, rep_len, "Don't support parameter %s\n", argv[3]);
			else
				pos += spdia_print_param_value(param, pos, end - pos);
		}
	} else if (strcmp("set", argv[1]) == 0) {
		if (argc <= 3)
			return spdia_print_ctrl_usage(argv[0], rep, rep_len);

		pos += spdia_set_param_value(argv[2], argv[3], pos, end - pos);
	} else if (strcmp("diag", argv[1]) == 0) {
		if (argc <= 2)
			return spdia_print_ctrl_usage(argv[0], rep, rep_len);

		if (strcmp("show", argv[2]) == 0) {
			pos += spdia_print_diagnosed_sta(pos, end - pos);
		} else if ((strcmp("add", argv[2]) == 0) && argc >= 4) {
			uint16_t period = 50;
			uint8_t reorder = 1, mode_data = 1, mode_ndp = 0, ng = 1,
				mode, smooth = 0;
			if (spdia_parse_diag_sta_config(argv, argc, &period, &reorder,
				&mode_data, &mode_ndp, &ng, &smooth) < 0)
				return spdia_print_config_usage(argv[3], rep, rep_len);
			else
				pos += snprintf(pos, end - pos, "success\n");
			mode = (mode_data << SPDIA_MODE_DATA_SHIFT) |
				(mode_ndp << SPDIA_MODE_NDP_SHIFT);
			spdia_add_diagnosed_sta(argv[3], period, reorder, mode, ng, smooth);
		} else if ((strcmp("del", argv[2]) == 0) && argc >= 4) {
			if (spdia_del_diagnosed_sta(argv[3]) < 0)
				pos += snprintf(pos, end - pos, "failed\n");
			else
				pos += snprintf(pos, end - pos, "success\n");
		} else {
			pos += spdia_print_ctrl_usage(argv[0], rep, rep_len);
		}
	}else {
		return spdia_print_ctrl_usage(argv[0], rep, rep_len);
	}

__out:
	return pos - rep;
}

static char g_req[SPDIA_CTRL_LEN];
static char g_rep[SPDIA_CTRL_LEN];
void spdia_recv_ctrl_frame(spdia_ctx_t *spdia_ctx)
{
	int nread, rep_len;
	struct sockaddr_un addr;
	socklen_t addr_len;

	memset(g_req, 0, SPDIA_CTRL_LEN);
	memset(g_rep, 0, SPDIA_CTRL_LEN);

	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	nread = recvfrom(g_ctx.ctrl_sock, g_req,
		SPDIA_CTRL_LEN, MSG_DONTWAIT, (struct sockaddr *)&addr, &addr_len);

	if (nread < 0) {
		SPDIA_WARN("Failed to receive frame from ctrl socket: %s\n", strerror(errno));
		return;
	}

	rep_len = spdia_ctrl_handle_req(g_req, nread, g_rep, SPDIA_CTRL_LEN);
	if(rep_len < 0) {
		SPDIA_WARN("Failed to handle the ctrl req: %d\n", rep_len);
		return;
	}


	if (sendto(g_ctx.ctrl_sock, g_rep, rep_len,
		0, (struct sockaddr *)&addr, addr_len) < 0)
		SPDIA_WARN("Failed to send frame to ctrl socket: %s\n", strerror(errno));
}

