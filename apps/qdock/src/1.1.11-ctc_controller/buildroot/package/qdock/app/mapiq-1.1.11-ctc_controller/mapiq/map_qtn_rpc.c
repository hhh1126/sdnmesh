/*
 *  Copyright (c) 2018-2019, Semiconductor Components Industries, LLC
 *  ("ON Semiconductor")   f/k/a Quantenna. All rights reserved.
 *  This software and/or documentation is licensed by ON Semiconductor under
 *  limited terms and conditions.  The terms and conditions pertaining to the
 *  software and/or documentation are available at
 *  http://www.onsemi.com/site/pdf/ONSEMI_T&C.pdf ("ON Semiconductor Standard
 *  Terms and Conditions of Sale, Section 8 Software").  Reproduction and
 *  redistribution in binary form, without modification, for use solely in
 *  conjunction with a Quantenna chipset, is permitted with an executed
 *  Quantenna Software Licensing Agreement and in compliance with the terms
 *  therein and all applicable laws. Do not use this software and/or
 *  documentation unless you have carefully read and you agree to the limited
 *  terms and conditions.  By using this software and/or documentation, you
 *  agree to the limited terms and conditions.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "qcsapi_output.h"
#include "qcsapi.h"
#include "qcsapi_rpc/client/qcsapi_rpc_client.h"
#include "qcsapi_rpc/generated/qcsapi_rpc.h"
#include "qcsapi_rpc_common/common/rpc_raw.h"
#include "qcsapi_rpc_api.h"
#include "map_extcfg_qtn.h"

#define REMOTE_CONNECT_RETRY_TIMES 3
static int qcs_init_flag = 0;

extern CLIENT *clnt_pci_create(const char *hostname,
			       u_long prog, u_long vers, const char *proto);

static  CLIENT *qtn_remote = NULL;
#define MAX_STR_LEN 32
#define RAW_SOCK_CONFIG_FILE	"/tmp/qtn_raw_mac.conf"
#define IP_SOCK_CONFIG_FILE		"/tmp/qtn_rpc_ip.conf"
#define HOST_IFNAME_FILE		"/tmp/qtn_host_ifname.conf"
#define TARGET_IFNAME_FILE		"/tmp/qtn_target_ifname.conf"
#define MAC_PRINT_FORMAT 		"%02x:%02x:%02x:%02x:%02x:%02x"
#define IP_PRINT_FORMAT 		"%d.%d.%d.%d"

char hostif_ifname[IFNAME_MAXLEN] = {0};
char targetif_ifname[IFNAME_MAXLEN] = {0};
char *hostif_ptr = NULL;
char *targetif_ptr = NULL;

int qtn_get_host_ifname(void)
{
	char *fret;
	int ret = -1;
	static char ifname_buf[MAX_STR_LEN];
	FILE *file = fopen(HOST_IFNAME_FILE, "r");
	if (file) {
		fret = fgets(ifname_buf, MAX_STR_LEN, file);
	}
	else {
		EXTCFG_ERROR("cannot get host ifname from %s\n",
			HOST_IFNAME_FILE);
		return -1;
	}

	if (fret || feof(file)) {
		ret =
		    sscanf(ifname_buf, "%s", hostif_ifname);
		if (ret > 0)
			hostif_ptr = hostif_ifname;
	}
	else {
		EXTCFG_ERROR("read host interface name error\n");
	}
	fclose(file);
	return ret;
}

int qtn_read_raw_sock_mac(uint8_t * target_mac)
{
	char *fret;
	int ret = -1, i;
	unsigned int intmac[6];
	int blank_mac_bit = 0;
	static char hostbuf[MAX_STR_LEN];

	FILE *file = fopen(RAW_SOCK_CONFIG_FILE, "r");
	if (file)
		fret = fgets(hostbuf, MAX_STR_LEN, file);
	else
		return -1;

	if (fret || feof(file)) {
		ret =
		    sscanf(hostbuf, MAC_PRINT_FORMAT, &intmac[0], &intmac[1],
			   &intmac[2], &intmac[3], &intmac[4], &intmac[5]);
		for (i = 0; i < 6; i++) {
			target_mac[i] = (uint8_t)intmac[i];
			if (target_mac[i] == 0)
				blank_mac_bit++;
		}
		if (blank_mac_bit == 6) {
			EXTCFG_ERROR("mac address at %s are all zero\n",
				RAW_SOCK_CONFIG_FILE);
			fclose(file);
			return ret;
		}
		fclose(file);
		ret = 0;
		return ret;
	} else {
		EXTCFG_ERROR("read mac error\n");
		memset(target_mac, 0, 6);

		fclose(file);
		return ret;
	}
}

static int qtn_read_rpc_sock_ip(char * target_ip)
{
	char *fret;
	struct sockaddr_in sa;
	static char hostbuf[MAX_STR_LEN] = {0};
	static char filebuf[MAX_STR_LEN] = {0};
	unsigned int intip[4];

	FILE *file = fopen(IP_SOCK_CONFIG_FILE, "r");
	if (file)
		fret = fgets(filebuf, MAX_STR_LEN, file);
	else
		return -1;

	if (fret || feof(file)) {
		sscanf(filebuf, IP_PRINT_FORMAT, &intip[0], &intip[1],
			&intip[2],  &intip[3]);
		sprintf(hostbuf, IP_PRINT_FORMAT, intip[0], intip[1],
			intip[2],  intip[3]);
		if( !inet_pton(AF_INET, hostbuf, &(sa.sin_addr))) {
			EXTCFG_ERROR("ip format at %s is incorrect\n",
				IP_SOCK_CONFIG_FILE);
			fclose(file);
			return -1;
		}

		sprintf(target_ip, "%s", hostbuf);

		fclose(file);
		return 0;
	} else {
		EXTCFG_ERROR("reading mac error");
		fclose(file);
		return -1;
	}
}

void qtn_rpc_disconnect(void)
{
	if (qtn_remote != NULL) {
		clnt_destroy(qtn_remote);
		qtn_remote = NULL;
		client_qcsapi_set_rpcclient(NULL);
	}
}

#ifdef Q_OPENWRT
int qtn_rpc_connect(const char *p_host)
#else
int qtn_rpc_connect(void)
#endif
{
	int retry = 0;

	do {
		uint8_t target_mac[6] = { 0 };
		char host[16] = { 0 };

		if (qtn_remote != NULL)
			clnt_destroy(qtn_remote);

		if ( !qtn_read_raw_sock_mac(target_mac) ) {
			if (!hostif_ptr && (qtn_get_host_ifname() < 0)) {
				EXTCFG_ERROR("cannot get host interface name properly\n");
				return -1;
			}
			qtn_remote = qrpc_clnt_raw_create(QCSAPI_PROG, QCSAPI_VERS, hostif_ptr, target_mac, QRPC_QCSAPI_RPCD_SID);
		}
		else if ( !qtn_read_rpc_sock_ip(host) ) {
			qtn_remote = clnt_create(host, QCSAPI_PROG, QCSAPI_VERS, "tcp");
#ifdef Q_OPENWRT
		}
		else if (p_host) {
			EXTCFG_DEBUG("host ip: %s\n", p_host);
			qtn_remote = clnt_create(p_host, QCSAPI_PROG, QCSAPI_VERS, "tcp");
#endif
		} else {
			qtn_remote = clnt_pci_create(host, QCSAPI_PROG, QCSAPI_VERS, NULL);
		}
		if (qtn_remote == NULL) {
			clnt_pcreateerror(host);
			EXTCFG_ERROR("cannot find the connection service\n");
			sleep(1);
			continue;
		} else {
			client_qcsapi_set_rpcclient(qtn_remote);
			if (!qcs_init_flag) {
				if (qcsapi_init() >= 0) {
					qcs_init_flag = 1;
				}
				else {
					qtn_remote = NULL;
					client_qcsapi_set_rpcclient(NULL);
					return -2;
				}
			}
			return 0;
		}
	} while (retry++ < REMOTE_CONNECT_RETRY_TIMES);

	return -2;
}

