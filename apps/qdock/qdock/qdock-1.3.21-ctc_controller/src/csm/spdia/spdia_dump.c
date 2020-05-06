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

#ifdef SPDIA_SUPPORT_FILE_DUMP

#define SPDIA_PRINT	spdia_dump_print

typedef struct spdia_dump_limit {
	uint32_t dumped;
	uint32_t missed;
	struct timeval begin;
} spdia_dump_limit_t;

static spdia_dump_limit_t g_limit;

#define SPDIA_DUMP_FNAME	"/tmp/.spdia_dump"
typedef struct {
	uint8_t ind;
	FILE *file;
} spdia_dump_t;

static spdia_dump_t g_dump;

static void spdia_dumpfile_switch(void)
{
	char file_name[NAME_MAX];
	struct stat file_stat;

	if (NULL == g_dump.file) {
		g_dump.ind = 0;
	} else if (0 == fstat(fileno(g_dump.file), &file_stat)
		&& file_stat.st_size > (g_ctx.cfg.dump_kbytes << 10)) {
		fclose(g_dump.file);
		g_dump.ind++;
	} else {
		return;
	}

	snprintf(file_name, NAME_MAX, SPDIA_DUMP_FNAME "_%02u", (g_dump.ind & 0x01));
	g_dump.file = fopen(file_name, "w");
}

static inline void spdia_dump_print(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(g_dump.file, fmt, ap);
	va_end(ap);
}

static inline int32_t spdia_time_sub(struct timeval *a, struct timeval *b)
{
	int32_t sec = a->tv_sec - b->tv_sec;
	int64_t usec = a->tv_usec - b->tv_usec;
	if (usec < 0) {
		sec--;
		usec += 1000000;
	}

	return sec * 1000 + usec / 1000;
}

static int spdia_dump_ratelimit(void)
{
	spdia_cfg_t *cfg = &g_ctx.cfg;
	struct timeval now;
	if (!cfg->dump_interval)
		return 1;
	if (!cfg->dump_burst)
		return 0;

	gettimeofday(&now, NULL);
	if (!g_limit.begin.tv_sec
		&& !g_limit.begin.tv_usec)
		memcpy(&g_limit.begin, &now, sizeof(now));

	if (spdia_time_sub(&now, &g_limit.begin)
		>= cfg->dump_interval) {
		if (g_limit.missed)
			SPDIA_PRINT("Dump callbacks(%u) suppressed\n", g_limit.missed);
		memset(&g_limit, 0, sizeof(g_limit));
	}

	if (cfg->dump_burst > g_limit.dumped) {
		g_limit.dumped++;
		return 1;
	}

	g_limit.missed++;
	return 0;
}

static void spdia_dump_head_line(spdia_info_t *info, csmmsgh_t *h)
{
	SPDIA_PRINT("%010llu " SPDIA_MACFMT " --> " SPDIA_MACFMT ":\n",
		info->timestamp, SPDIA_MACARG(info->mac), SPDIA_MACARG(h->bssid));
}

static void spdia_dump_bref_info(spdia_info_t *info, csmmsgh_t *h)
{
	spdia_dump_head_line(info, h);
#ifdef PLATFORM_PEARL
	SPDIA_PRINT("\tRSSI Vector: %04d %04d %04d %04d %04d %04d %04d %04d/ %04d\n",
                info->rssis[0], info->rssis[1], info->rssis[2], info->rssis[3],
		info->rssis[4], info->rssis[5], info->rssis[6], info->rssis[7],
                info->hw_noise);
#else
	SPDIA_PRINT("\tRSSI Vector: %04d %04d %04d %04d / %04d\n",
		info->rssis[0], info->rssis[1], info->rssis[2],
		info->rssis[3], info->hw_noise);
#endif
	SPDIA_PRINT("\tMatric: %02u X %02u; Group %02u; Tones %03u\n",
		info->nr, info->nc, info->ng, info->ntones);
	SPDIA_PRINT("\tChan: %03u; BW %uMHz; Mode %s; MCS %02x(%u)\n",
		info->chan, 20 * (1 << info->bw),
		info->bf_mode == 0 ? "11n" : "11ac",
		info->mcs, info->mcs_ss);
	SPDIA_PRINT("\tSPDIA payload(%lu):\n", info->head.size - sizeof(*info));
}

static void spdia_dump_raw_data(const char *ident, uint8_t *data, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		if ((i != 0) && ((i & 0x0f) == 0))
			SPDIA_PRINT("\n");
		else if ((i != 0) && ((i & 0x07) == 0))
			SPDIA_PRINT("   ");

		if ((i & 0x0f) == 0)
			SPDIA_PRINT("%s ", ident);
		SPDIA_PRINT("%02x ", data[i]);
	}
	SPDIA_PRINT("\n");
}

static void spdia_dump_compact_info(spdia_info_t *info, uint8_t *csi, csmmsgh_t *h)
{
	spdia_dump_bref_info(info, h);
	spdia_dump_raw_data("\t\t", csi, info->head.size - sizeof (*info));
}

static void spdia_dump_info_event(spdia_info_t *info, csmmsgh_t *h)
{
	spdia_dump_head_line(info, h);
	spdia_dump_raw_data("\t", (uint8_t *)h,
		le_to_host16(h->payload_len) + sizeof(*h));
}
#endif

#ifdef SPDIA_SUPPORT_TCP_DUMP
static void inline spdia_dump_release_connection(void)
{
	char *addrp = inet_ntoa(g_ctx.client_addr.sin_addr);
	SPDIA_DEBUG("client(%s %u) closed\n", addrp ? addrp : "unknown",
		ntohs(g_ctx.client_addr.sin_port));

	close(g_ctx.dump_client_sock);
	g_ctx.dump_client_sock = -1;
	memset(&g_ctx.client_addr, 0, sizeof(g_ctx.client_addr));
}

void spdia_recv_dump_connect(void)
{
	char *addrp;
	struct sockaddr_in addr;
	uint32_t len = sizeof(addr);
	int sd = accept(g_ctx.dump_server_sock, (struct sockaddr *)&addr, &len);
	if (sd < 0) {
		SPDIA_ERROR("dump server sock accept failed(%u): %s\n",
			errno, strerror(errno));
		return;
	}

	addrp = inet_ntoa(addr.sin_addr);
	SPDIA_DEBUG("connect request from client %s(%u)\n",
		addrp ? addrp : "unknown", ntohs(addr.sin_port));

	pthread_mutex_lock(&g_ctx.dump_mutex);
	if (g_ctx.dump_client_sock >= 0)
		spdia_dump_release_connection();
	g_ctx.dump_client_sock = sd;
	memcpy(&g_ctx.client_addr, &addr, sizeof(addr));
	pthread_mutex_unlock(&g_ctx.dump_mutex);
}

void spdia_recv_dump_client(void)
{
	uint8_t tbuf[128];
	int nread;

	if (g_ctx.dump_client_sock < 0)
		return;

	nread = recv(g_ctx.dump_client_sock,
		tbuf, 128, MSG_DONTWAIT);

	if (nread <= 0) {
		if (errno == EAGAIN
			|| errno == EINTR)
			return;
		SPDIA_WARN("client dis-connect dump server(%u): %s\n",
			errno, strerror(errno));
		spdia_dump_release_connection();
	}
}

static void spdia_dump_data_to_client(uint8_t *data, uint32_t len)
{
	int nwrite, total = 0;

	if (g_ctx.dump_client_sock < 0)
		return;

	while (total < len) {
		nwrite = send(g_ctx.dump_client_sock,
			data + total, len - total, MSG_NOSIGNAL);
		if (nwrite <= 0) {
			if (errno == EAGAIN
				|| errno == EINTR)
				continue;
			SPDIA_DEBUG("sent failed(%u): %s\n", errno, strerror(errno));
			spdia_dump_release_connection();
			break;
		}
		total += nwrite;
	}

	SPDIA_DEBUG("sent bytes %d to client\n", total);
}

static void spdia_dump_to_client(spdia_info_t *info, uint8_t *csi)
{
	int i;
	spdia_info_t tmp;
	memcpy(&tmp, info, sizeof(tmp));

	tmp.head.type = host_to_le32(tmp.head.type);
	tmp.head.size = host_to_le32(tmp.head.size);
	tmp.timestamp = host_to_le64(tmp.timestamp);
	for (i = 0; i < SPDIA_CHAINS; i++)
		tmp.rssis[i] = host_to_le32(tmp.rssis[i]);
	tmp.hw_noise = host_to_le32(tmp.hw_noise);
	tmp.ntones = host_to_le32(tmp.ntones);

	pthread_mutex_lock(&g_ctx.dump_mutex);
	spdia_dump_data_to_client((uint8_t *)&tmp, sizeof(tmp));
	spdia_dump_data_to_client(csi, info->head.size - sizeof(tmp));
	pthread_mutex_unlock(&g_ctx.dump_mutex);
}
#endif

#if defined (SPDIA_SUPPORT_TCP_DUMP) || defined (SPDIA_SUPPORT_FILE_DUMP)
void spdia_dump_info(spdia_info_t *info, uint8_t *csi, csmmsgh_t *h)
{
#ifdef SPDIA_SUPPORT_TCP_DUMP
	spdia_dump_to_client(info, csi);
#endif

#ifdef SPDIA_SUPPORT_FILE_DUMP
	if (!spdia_dump_ratelimit())
		return;

	spdia_dumpfile_switch();
	if (!g_dump.file)
		return;

	switch (g_ctx.cfg.dump_level) {
	case SPDIA_DUMP_NONE:
		break;
	case SPDIA_DUMP_BREF:
		spdia_dump_bref_info(info, h);
		break;
	case SPDIA_DUMP_COMPACT:
		spdia_dump_compact_info(info, csi, h);
		break;
	default:
		spdia_dump_info_event(info, h);
		break;
	}
#endif
}

void spdia_init_dump_cfg(void)
{
#ifdef SPDIA_SUPPORT_FILE_DUMP
	g_ctx.cfg.dump_level = SPDIA_DUMP_DETAIL;
	g_ctx.cfg.dump_interval = 100;
	g_ctx.cfg.dump_burst = 2;
	g_ctx.cfg.dump_kbytes = 500;
#endif
#ifdef SPDIA_SUPPORT_TCP_DUMP
	g_ctx.cfg.dump_port = 50005;
#endif
}

int spdia_dump_init(void)
{
#ifdef SPDIA_SUPPORT_TCP_DUMP
	int optval = 1;
	struct sockaddr_in addr;
	int sd;
#endif

#ifdef SPDIA_SUPPORT_FILE_DUMP
	memset(&g_limit, 0, sizeof(g_limit));
	memset(&g_dump, 0, sizeof(g_dump));
#endif

#ifdef SPDIA_SUPPORT_TCP_DUMP
	pthread_mutex_init(&g_ctx.dump_mutex, NULL);
	g_ctx.dump_server_sock = -1;
	g_ctx.dump_client_sock = -1;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		SPDIA_ERROR("dump server sock create failed(%d): %s\n",
			errno, strerror(errno));
		return -1;
	}
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval , sizeof(optval)) < 0)
		SPDIA_WARN("dump server sock setopt failed(%d): %s\n",
			errno, strerror(errno));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons((uint16_t)g_ctx.cfg.dump_port);

	if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sd);
		SPDIA_ERROR("dump server sock bind failed(%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	if (listen(sd, 1) < 0) {
		close(sd);
		SPDIA_ERROR("dump server sock listen failed(%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	g_ctx.dump_server_sock = sd;
#endif
	return 0;
}

void spdia_dump_deinit(void)
{
#ifdef SPDIA_SUPPORT_FILE_DUMP
	if (g_dump.file)
		fclose(g_dump.file);
	g_dump.file = NULL;
#endif

#ifdef SPDIA_SUPPORT_TCP_DUMP
	if (g_ctx.dump_server_sock >= 0)
		close(g_ctx.dump_server_sock);
	if (g_ctx.dump_client_sock >= 0)
		close(g_ctx.dump_client_sock);
	g_ctx.dump_server_sock = -1;
	g_ctx.dump_client_sock = -1;
#endif
}

#endif
