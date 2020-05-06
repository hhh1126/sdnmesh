/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.                  **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/

#include <stdio.h>
#include "qsteer_comm_ext.h"

int main(int argc, char *argv[])
{
	int ret;
	FILE *fp;
	qsteer_role_t role;

	if (argc != 2) {
		printf("Usage: %s CFG_FILE\n", argv[0]);
		return 1;
	}

	if (qsteer_get_role(&role) != 0) {
		printf("Failed to get the current role\n");
		return 1;
	}

	if (role != QSTEER_ROLE_MASTER) {
		printf("Can only update AP configuration on master\n");
		return 1;
	}

	if (qsteer_cfg_update(argv[1]) != 0) {
		printf("Failed to update the AP configuration\n");
		return 1;
	}

	while (1) {
		ret = qsteer_get_update_fdbk("/tmp/qsteer_update_fdbk");
		if (ret == 1) {
			/* updating is in process */
			sleep(1);
			continue;
		} else if (ret < 0) {
			printf("Failed to get the updating feedback\n");
			break;
		} else {
			printf("Finish updating, the feedback is saved in /tmp/qsteer_update_fdbk\n");
			break;
		}
	}

	return 0;
}
