/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.                  **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cfg_ext.h"

#define QWEBCFG_CMD "/usr/sbin/qwebcfg"
#define QCSAPI_CMD "/sbin/call_qcsapi"

#define IEEE80211_EXTENDER_ROLE_NONE 0
#define IEEE80211_EXTENDER_ROLE_MBS  1
#define IEEE80211_EXTENDER_ROLE_RBS  2

#define MODE_UNKNOW 	0
#define MODE_AP 	1
#define MODE_STA 	2
#define MODE_REPEATER 	3
#define MODE_QHOP_MBS 	4
#define MODE_QHOP_RBS 	5
#define MODE_QHOP_STA 	6

typedef struct radio_info {
	const char *name;
} radio_info_t;

static radio_info_t radios[] = {
#ifdef PEARL_PLATFORM
	{"wifi0_0"},
	{"wifi2_0"},
#else
	{"wifi0"},
#endif
};

#define RADIO_NUM (sizeof(radios) / sizeof(radios[0]))

int get_qcsapi_cmd_result(const char *cmd, char *res, int res_len)
{
	char buf[512];
	FILE *fp = NULL;

	if(cmd == NULL)
		return -1;

	res[0] = 0;
	if ((fp = popen(cmd, "r")) != NULL) {
		while (fgets(buf, 512, fp) != NULL) {
			if (strlen(res) + strlen(buf) > res_len)
				break;
			strcat(res, buf);
		}
		pclose(fp);
		fp = NULL;
	} else {
		return -1;
	}
	return 0;
}

int get_qtna_work_mode(int ind)
{
	char cmd[512];
	char res[512];
	int role = IEEE80211_EXTENDER_ROLE_NONE;
	int ret;

	if (access(QCSAPI_CMD, X_OK) != 0)
		return -1;

	ret = snprintf(cmd, sizeof(cmd), "%s verify_repeater_mode", QCSAPI_CMD);
	if (ret >= sizeof(cmd))
		return -1;

	if (get_qcsapi_cmd_result(cmd, res, sizeof(res)) < 0)
		return -1;

	if (atoi(res) == 1)
		return MODE_REPEATER;

	ret = snprintf(cmd, sizeof(cmd), "%s get_extender_status %s", QCSAPI_CMD, radios[ind].name);
	if (ret >= sizeof(cmd))
		return -1;

	if (get_qcsapi_cmd_result(cmd, res, sizeof(res)) < 0)
		return -1;

	if (!strncasecmp(res, "role: NONE", 10))
		role = IEEE80211_EXTENDER_ROLE_NONE;
	else if (!strncasecmp(res, "role: RBS", 9))
		role = IEEE80211_EXTENDER_ROLE_RBS;
	else if (!strncasecmp(res, "role: MBS", 9))
		role = IEEE80211_EXTENDER_ROLE_MBS;

	ret = snprintf(cmd, sizeof(cmd), "%s get_mode %s", QCSAPI_CMD, radios[ind].name);
	if (ret >= sizeof(cmd))
		return -1;

	if (get_qcsapi_cmd_result(cmd, res, sizeof(res)) < 0)
		return -1;

	if(!strncasecmp(res, "Access point", 12)) {
		switch (role) {
		case IEEE80211_EXTENDER_ROLE_MBS:
			return MODE_QHOP_MBS;
		case IEEE80211_EXTENDER_ROLE_RBS:
			return MODE_QHOP_RBS;
		default:
			return MODE_AP;
		}
	} else if (!strncasecmp(res, "Station", 7)) {
		switch (role) {
		case IEEE80211_EXTENDER_ROLE_RBS:
			return MODE_QHOP_STA;
		default:
			return MODE_STA;
		}
	}
	return MODE_UNKNOW;
}

int qsteer_master_mode_allowed(void)
{
	int i;
	int mode = MODE_UNKNOW;

	for (i = 0; i < RADIO_NUM; i++) {
		if ((mode = get_qtna_work_mode(i)) < 0)
			return -1;

		if (mode != MODE_AP &&
		    mode != MODE_QHOP_MBS)
			return 0;
	}
	return 1;
}

int qsteer_get_cfg(const char *path)
{
	char cmd[512];
	int ret;

	if (!path)
		return -1;

	if (access(QWEBCFG_CMD, X_OK) != 0)
		return -1;

	ret = snprintf(cmd, sizeof(cmd), "%s get %s", QWEBCFG_CMD, path);
	if (ret >= sizeof(cmd))
		return -1;

	ret = system(cmd);
	if (ret != 0)
		return -1;

	return 0;
}

int qsteer_set_cfg(const char *path)
{
	char cmd[512];
	int ret;

	if (!path)
		return -1;

	if (access(QWEBCFG_CMD, X_OK) != 0)
		return -1;

	ret = snprintf(cmd, sizeof(cmd), "%s set %s", QWEBCFG_CMD, path);
	if (ret >= sizeof(cmd))
		return -1;

	ret = system(cmd);
	if (ret != 0)
		return -1;

	return 0;
}

void qsteer_report_update_feedback(const char *path)
{
	char cmd[512];
	int ret;

	if (!path)
		return;

	ret = snprintf(cmd, sizeof(cmd), "cat %s", path);
	if (ret >= sizeof(cmd))
		return;

	system(cmd);
}

int qsteer_apply_local_cfg(void)
{
	return 0;
}
