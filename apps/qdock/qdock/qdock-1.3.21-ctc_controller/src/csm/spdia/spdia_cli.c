/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          		 **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include "spdia_common.h"
#include "spdia_cli.h"

static char cli_path[512];

static int spdia_ctrl_cli_sock_open()
{
	int sd;
	struct sockaddr_un addr;
	int path_len;

	path_len = sprintf(cli_path, "%s-cli-%d", SPDIA_UNIX_PATH, getpid());
	if (path_len >= sizeof(addr.sun_path)) {
		printf("sun_path oversize\n");
		return -1;
	}

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0) {
		printf("Failed to open PF_UNIX socket: %s\n", strerror(errno));
		return -1;
	}

	unlink(cli_path);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, cli_path, sizeof(addr.sun_path) - 1);
	if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("Failed to bind to %s: %s\n", addr.sun_path, strerror(errno));
		close(sd);
		return -1;
	}

	return sd;
}

static int spdia_ctrl_cli_req(int sd, char *req, int req_len)
{
	char *rep;
	struct timeval timeout;
	struct sockaddr_un addr;
	socklen_t addr_len;

	if(NULL == (rep = calloc(SPDIA_CTRL_LEN + 1, sizeof(char)))) {
		printf("can not alloc rep\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SPDIA_UNIX_PATH);
	addr_len = sizeof(addr);

	if (sendto(sd, req, req_len, 0, (struct sockaddr *)&addr, addr_len) < 0) {
		printf("Failed to send cmd to QTN-Comm-M: %s\n", strerror(errno));
		goto __ret;
	}

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		printf("Failed to set recv timeout: %s\n", strerror(errno));
		goto __ret;
	}

	if (recvfrom(sd, rep, SPDIA_CTRL_LEN, 0, (struct sockaddr *)&addr, &addr_len) < 0) {
		printf("Failed to receive cli output from QSL: %s\n", strerror(errno));
		goto __ret;
	}
	rep[SPDIA_CTRL_LEN] = '\0';
	printf("%s", rep);

__ret:
	free(rep);

	return 0;
}

static char g_req[SPDIA_CTRL_LEN];

int main(int argc, char *argv[])
{
	int sd, i;
	char *pos;

	if (argc > 255) {
		printf("Too many parameters\n");
		return -1;
	}

	sd = spdia_ctrl_cli_sock_open();
	if (sd < 0)
		return -1;

	memset(g_req, 0, sizeof(g_req));
	g_req[0] = argc;
	pos = &g_req[1];
	for (i = 0; i < argc; ++i, ++pos) {
		pos += snprintf(pos, SPDIA_CTRL_LEN - (pos - g_req), "%s", argv[i]);
		if(pos - g_req >= SPDIA_CTRL_LEN) {
			printf("cli len over 128\n");
			break;
		}
	}

	spdia_ctrl_cli_req(sd, g_req, pos - g_req);

	close(sd);
	unlink(cli_path);

	return 0;
}
