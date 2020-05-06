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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "qsteer_comm_ext.h"

#define QWEBCFG_CMD "/usr/sbin/qwebcfg"

int qsteer_get_role(qsteer_role_t *role)
{
	if (!role)
		return -1;

	*role = QSTEER_ROLE_UNCONFIGURED;

	return 0;
}

int qsteer_cfg_update(const char *path)
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

int qsteer_get_update_fdbk(const char *path)
{
	FILE *fp;

	if (!path)
		return -1;

	fp = fopen(path, "w");
	if (!fp) {
		printf("Failed to open %s for writing: %s\n", path, strerror(errno));
		return -1;
	}

	fprintf(fp, "success=TRUE\n");
	fprintf(fp, "reconf_master=TRUE\n");
	fprintf(fp, "n_failed_slaves=0\n");

	fprintf(fp, "list_failed_slaves={\n");
	fprintf(fp, "}\n");

	fclose(fp);

	return 0;
}
