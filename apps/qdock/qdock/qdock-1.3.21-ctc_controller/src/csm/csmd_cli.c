/*SH0:
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "csmd_cli.h"

#define PPREFIX "csmd_cli: "
static char cli_path[512];


static int ctrl_cli_sock_open()
{
	int sd;
	struct sockaddr_un addr;
	int path_len;

	path_len =
	    sprintf(cli_path, "%s-cli-%d", CSMD_CLI_UN_PATH, getpid());
	if (path_len >= sizeof(addr.sun_path)) {
		printf(PPREFIX "sun_path oversize\n");
		return -1;
	}

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0) {
		printf(PPREFIX "Failed to open PF_UNIX socket: %s\n",
		       strerror(errno));
		return -1;
	}

	unlink(cli_path);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, cli_path, sizeof(addr.sun_path) - 1);
	if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf(PPREFIX "Failed to bind to %s: %s\n", addr.sun_path,
		       strerror(errno));
		close(sd);
		return -1;
	}

	return sd;
}

static int ctrl_cli_req(int sd, char *req, int req_len)
{
	char rep[MAX_CTRL_MSG_LEN + RESERVE_LEN] = { 0 };
	struct timeval timeout;
	struct sockaddr_un addr;
	socklen_t addr_len;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, CSMD_CLI_UN_PATH);
	addr_len = sizeof(addr);

	if (sendto
	    (sd, req, req_len, 0, (struct sockaddr *) &addr,
	     addr_len) < 0) {
		printf(PPREFIX "Failed to send cmd to csmd: %s\n",
		       strerror(errno));
		return 0;
	}

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	if (setsockopt
	    (sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		printf(PPREFIX "Failed to set recv timeout: %s\n",
		       strerror(errno));
		return 0;
	}

	do {
		memset(rep, 0, sizeof(rep));
		if (recvfrom(sd, rep, sizeof(rep), 0,
			(struct sockaddr *) &addr, &addr_len) < 0) {
			printf(PPREFIX "Failed to receive output from csmd: %s\n",
				strerror(errno));
			return -2;
		}
		printf("%s", VALID_CTRL_MSG_HEAD(rep));
	} while(rep[0] != CTRL_MSG_END);

	return 0;
}

int main(int argc, char *argv[])
{
	int sd, i;
	char req[MAX_CTRL_MSG_LEN] = { 0 };
	char *pos;

	if (argc > 255) {
		printf(PPREFIX "Too many parameters\n");
		return -1;
	}

	sd = ctrl_cli_sock_open();
	if (sd < 0)
		return -1;

	req[0] = argc;
	pos = &req[1];
	for (i = 0; i < argc && pos < req + MAX_CTRL_MSG_LEN; ++i, ++pos)
		pos += snprintf(pos, req + MAX_CTRL_MSG_LEN - pos, "%s", argv[i]);

	ctrl_cli_req(sd, req, pos - req);

	close(sd);
	unlink(cli_path);

	return 0;
}
