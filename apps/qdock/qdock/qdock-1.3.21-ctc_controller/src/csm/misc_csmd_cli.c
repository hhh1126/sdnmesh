/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <inttypes.h>
#include "version.h"
#include "qsteer.h"
#include "csmd_cli.h"

#define NAME "misc.qtn.csmdcli"
#define PPREFIX "[Misc - "NAME"]: "

static char req[MAX_CTRL_MSG_LEN];
static char rep[MAX_CTRL_MSG_LEN];

typedef int (*table_show_func_t) (void *, stah_t *, char *, int);

struct csmd_cli_desc {
	struct csm_plugin_file_desc desc;
	struct csm_misc_plugin *plugin[1];
};

struct csmd_cli {
	void *csm_ctx;
	int running;
	int ctrl_sock;
	pthread_t thread;
};

static int  csmd_cli_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage: csmd_cli <command>\n"
		"Commands:\n"
		"	show sta [<all/assoc/nassoc/bl>] [<verbose>]	: show sta table\n"
		"	show bss [<all>] [<verbose>]                	: show bss table\n"
		"	show radio					: show radio table\n"
		"	show backbone		                	: show bss backbone info table\n"
		"	dbg level/stdout <level>			: set dbg level\n"
		"	version						: get version\n"
		"	cmd <black/11v/erw/mbo/seen> <params>		: command for test\n"
		"		cmd erw <help>				: help for erw test command\n"
		" 		cmd mbo <help> 				: help for mbo test command\n"
		" 		cmd set_chan <help> 			: help for set channel test command\n"
		" 		cmd set_intf_cfg <help> 		: help for set intf cfg test command\n"
		" 		cmd roam <help> 			: help for roam test command\n"
		"\n");
}

static int csmd_cli_ctrl_sock_open()
{
	int sd;
	struct sockaddr_un addr;

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0)
		return -1;

	unlink(CSMD_CLI_UN_PATH);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, CSMD_CLI_UN_PATH);
	if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sd);
		return -1;
	}

	return sd;
}

#if 0
static const char *str_maxbw[] = {
	"20",
	"40",
	"80",
	"160",
};
#endif

static const char *node_type_string[] = {
	"UNKNOW",
	"VAP",
	"STA",
	"WDS",
	"TDSL",
	"REPEATER",
	"NOTWIFI",
};

static const char *csmd_node_type_to_string(enum csm_node_type type)
{
	if (type < (sizeof(node_type_string) / sizeof(char *)))
		return node_type_string[type];

	return "UNKONW";
}

#define YESORNO(value) ((value)?"Yes":"No")
#define BANDWIDTH_HT(value) ((value)?"20,40":"20")
#define BANDWIDTH_VHT(vht_op) (((vht_op)[2]==1)?((vht_op)[4]?",80,160,80+80":",80"):(((vht_op)[2]==2)?",160":(((vht_op)[2])==0?"":(((vht_op)[2]==3)?",80+80":",?"))))
#define BANDSTR(value) ((value)==BAND_2G?"2.4G":((value)==BAND_5G?"5G":"Undefined"))
#define RADIO_TABLE_HEADER	"                                                                    --- opclass/channels info --- \n"	\
				"      RADIO             ifType PWR  opcls chan maxVAPs FAT  age     opcls bw  pwr [ch: PR] \n"
#define RADIO_TABLE_INTF_HEADER	"                                                                    --- Interface info --- \n"	\
				"      RADIO             ifType PWR  opcls chan maxVAPs FAT  age     IntfMac           Type \n"
#define BSS_TABLE_HEADER "      BSSID             status  local  band  channel        supported bw  BSSTr   FAT        Slave        MDID ifType SSID\n"
#define STA_TABLE_HEADER "                         --- STA Max Capabilities ----  ---------- Current Association Info -----------  ----------- Seen by ---------------\n"	\
                           "      STA                 band  SS  bw  phyrate  BSSTr     AssocWithBSSID  MDID RSSI  MaxPhyR  AvgTX/RX  MDID             BSSID  RSSI   age  CH  Ref\n"
#define DEVID_TABLE_HEADER "      DEVID               refs         co-located\n"
#define BACKBONE_TABLE_HEADER "      BSSID               backbone backbn-phy uplink-local        Peer                Current PhyRate\n"

#define CSMD_CLI_SPRINTF(fmt, ...)	do { \
		pos += snprintf(pos, end - pos, fmt, ##__VA_ARGS__);	\
		if(pos >= end) goto _out;} while(0)

#define show_capability_details(_prefix_fmt, _cap)	\
	do {\
		CSMD_CLI_SPRINTF(_prefix_fmt "HT: %s, VHT: %s, mu-beamfomer: %s, mu-beamformee: %s\n", \
			YESORNO((_cap).ht_supported), \
			YESORNO((_cap).vht_supported), \
			YESORNO((_cap).mu_beamformer_supported), \
			YESORNO((_cap).mu_beamformee_supported));\
		CSMD_CLI_SPRINTF(_prefix_fmt "BSS Transition: %s\n", YESORNO((_cap).bss_transition_supported));\
	}while (0)

static int csmd_dump_buffer(char *rep, int rep_len, const char *prefix, uint8_t *buf, int len)
{
	int i;
	char *pos = rep, *end = rep + rep_len;
	CSMD_CLI_SPRINTF("%s", prefix);
	for (i = 0; i < len; i++) {
		CSMD_CLI_SPRINTF("%02x ", buf[i]);
		if (((i & 0x7) == 0x7) && (i != len - 1))
			CSMD_CLI_SPRINTF("\n%s", prefix);
	}
	CSMD_CLI_SPRINTF("\n");

_out:
	return pos - rep;
}

static int csmd_debug_filter_all(stah_t * stah, void *data1, void *data2)
{
	return 1;
}

static int csmd_debug_station_filter_associated_station(stah_t * stah,
							void *data1,
							void *data2)
{
	sta_table_t *sta = (sta_table_t *) stah;
	if ((sta->flag & (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED))
	    == (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED)
	    && (sta->node_type == NODE_TYPE_STA || sta->node_type == NODE_TYPE_REPEATER))
		return 1;
	else
		return 0;
}

static int csmd_debug_station_filter_blacklist_station(stah_t * stah,
							    void *data1,
							    void *data2)
{
	sta_table_t *sta = (sta_table_t *) stah;
	if (STA_IS_BLACKLISTED(sta)
		&& (sta->node_type == NODE_TYPE_STA || sta->node_type == NODE_TYPE_REPEATER))
		return 1;
	else
		return 0;
}

static int csmd_debug_station_filter_non_associated_station(stah_t * stah,
							    void *data1,
							    void *data2)
{
	sta_table_t *sta = (sta_table_t *) stah;
	if ((sta->flag & (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED))
	    == (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED))
		return 0;
	else
		return 1;
}

static int csmd_debug_station_filter_with_mac(stah_t * stah,
					      void *data1, void *data2)
{
	uint8_t *mac = data1;
	sta_table_t *sta = (sta_table_t *) stah;
	if (memcmp(sta->h.mac, mac, ETH_ALEN) == 0)
		return 1;
	else
		return 0;
}

#if 0
static uint32_t csmd_cli_bss_get_btm_bssinfo(bss_table_t * bss)
{
	uint8_t *cap = bss->capabilities_infomation;
	uint32_t value = BTM_AP_REACH | BTM_SECURITY | BTM_KEY_SCOPE;

	/* spectrum */
	value |= ((cap[1] & 0x01) ? 0x10 : 0);
	/* QoS */
	value |= ((cap[1] & 0x02) ? 0x20 : 0);
	/* APSD */
	value |= ((cap[1] & 0x08) ? 0x40 : 0);
	/* radio measurement */
	value |= ((cap[1] & 0x10) ? 0x80 : 0);
	/* delayed block ack */
	value |= ((cap[1] & 0x40) ? 0x100 : 0);
	/* immediate block */
	value |= ((cap[1] & 0x80) ? 0x200 : 0);

	/* high throughput */
	value |= ((bss->bss_capability.ht_supported) ? 0x800 : 0);
	/* very high throughput */
	value |= ((bss->bss_capability.vht_supported) ? 0x1000 : 0);

	return value;
}

#endif

static int csmd_cli_bss_trans(void *ctx, uint8_t * sta_mac,
			uint8_t * tgt_bssid)
{
	int ret = 0;
	csmctx_t *csm = GET_CSMCTX(ctx);
	sta_table_t *sta = csm_station_find(csm->station_db, sta_mac);
	bss_table_t *tgt_bss = csm_bss_find(csm->bss_db, tgt_bssid);
	csmmsg_t *msg;
	cmd_bss_trans_req_t *bt_req;

	if ((sta == NULL) || (tgt_bss == NULL)
		|| (!STA_IS_ASSOCIATED(sta))) {
		ret = -1;
		goto bail;
	}

	CSM_LOCK(sta);
	msg =
		csm_new_msg(CMD_BSS_TRANS_REQ, CSM_VER_2, CSM_CODING_FIXED,
			sta->assoc_info.assoc_bssid,
			sizeof(cmd_bss_trans_req_t));
	CSM_UNLOCK(sta);
	csm_station_put(sta);
	if (msg == NULL) {
		ret = -2;
		goto bail;
	}

	CSM_LOCK(tgt_bss);
	bt_req = (cmd_bss_trans_req_t *) csm_get_msg_body(msg);

	COPYMAC(bt_req->sta_mac, sta_mac);
	COPYMAC(bt_req->bssid, tgt_bssid);
	bt_req->bssid_info = 0;	//host_to_be32(csmd_cli_bss_get_btm_bssinfo(tgt_bss));
	bt_req->timer = host_to_be16(10);
	bt_req->validity = 0;
	bt_req->channel = tgt_bss->channel;
	bt_req->opclass = 8;	//tgt_bss->operation_class;
	bt_req->subel_len = 0;
	bt_req->phytype = tgt_bss->phy_type;
	bt_req->mode = 7;	/* prefered candidate included */
	CSM_UNLOCK(tgt_bss);
	csm_bss_put(tgt_bss);

	csm_push_cmd(ctx, msg);

bail:
	return ret;
}

static int csmd_cli_dump_bss(void *ctx, stah_t *stah, char *buf, int len)
{
	bss_table_t *bss = (bss_table_t *) stah;
	char supband[19];
	sprintf(supband, "%s%s", BANDWIDTH_HT(bss->bss_capability.ht_bw),
			(bss->bss_capability.vht_supported ?
			BANDWIDTH_VHT(bss->vht_operation) : ""));

	return snprintf(buf, len, "%" MACFMT "%7s  %5s  %4s  %7d  %18s  %5s  %4d  %" MACFMT "  %02x%02x %-6s %s\n",
			MACARG(bss->h.mac),
			(BSS_IS_UP(bss) ? "UP" : "DOWN"),
			(bss->ifname[0]) ? "Yes" : "No",
			BANDSTR(bss->band), bss->channel,
			supband,
			YESORNO(bss->bss_capability.bss_transition_supported),
			bss->fat,
			MACARG(bss->dev_id),
			bss->mdid[0], bss->mdid[1],
			csmd_node_type_to_string(bss->iftype),
			bss->ssid);
}

static inline const char *espi_ac_string(uint8_t ac)
{
	const char *ac_strs[] = {
		"AC_BK", "AC_BE", "AC_VI", "AC_VO"
	};

	if (ac >= ARRAY_SIZE(ac_strs))
		return "UNKNW";
	return ac_strs[ac];
}

static int csmd_cli_dump_espis(bss_table_t *bss, char *buf, int len)
{
	char *pos = buf, *end = buf + len;
	int i;

	CSMD_CLI_SPRINTF("\tESPIs:\n");
	for (i = 0; i < AC_MAXNUM; i++) {
		if (bss->espis[i].valid)
			CSMD_CLI_SPRINTF("\t\t%s %03u %03u %03u(50us)\n", espi_ac_string(i),
				bss->espis[i].format, bss->espis[i].window, bss->espis[i].duration);
	}

_out:
	return pos - buf;
}

static int csmd_cli_dump_bss_verbose(void *ctx, stah_t *stah, char *buf, int len)
{
	bss_table_t *bss = (bss_table_t *) stah;
	char *pos = buf, *end = buf + len;

	CSMD_CLI_SPRINTF("BSS[%" MACFMT "] on %s: %s, refcnt=%d\n",
		MACARG(bss->h.mac), bss->ifname,
		(BSS_IS_UP(bss) ? "UP" : "DOWN"), bss->h.obj.refcnt);
	CSMD_CLI_SPRINTF("\tintf type: %s\n", csmd_node_type_to_string(bss->iftype));
	if (bss->iftype == NODE_TYPE_VAP)
		CSMD_CLI_SPRINTF("\tssid: %s\n", bss->ssid);
	if (bss->iftype == NODE_TYPE_STA)
		CSMD_CLI_SPRINTF("\tbssid: %" MACFMT "\n", MACARG(bss->bssid));
	CSMD_CLI_SPRINTF("\tband: %s, channel: %d\n", BANDSTR(bss->band),
		bss->channel);
	CSMD_CLI_SPRINTF("\tbeacon_interval: %d\n", bss->binterval);
	CSMD_CLI_SPRINTF("\tdrivercap: 0x%x\n", bss->driver_cap);
	CSMD_CLI_SPRINTF("\text cap: 0x%08x\n", bss->ext_cap);
	CSMD_CLI_SPRINTF("\tIE capabality: 0x%02x%02x\n",
		bss->capabilities_infomation[1],
		bss->capabilities_infomation[0]);
	CSMD_CLI_SPRINTF("\tcapbility:       0x%x\n", bss->bss_capability.cap);
	show_capability_details("\t\t", bss->bss_capability);
	CSMD_CLI_SPRINTF("\t\tbandwidth(MHz): %s%s\n",
		BANDWIDTH_HT(bss->bss_capability.ht_bw),
		(bss->bss_capability.vht_supported ?
			BANDWIDTH_VHT(bss->vht_operation)
			: ""));
	CSMD_CLI_SPRINTF("\tphytype: %d\n", bss->phy_type);

	CSMD_CLI_SPRINTF("\thtcap[%d]:\n", HT_CAPABILITY_LEN);
	pos += csmd_dump_buffer(pos, end - pos, "\t\t", bss->ht_capability, HT_CAPABILITY_LEN);
	CSMD_CLI_SPRINTF("\thtop[%d]:\n", HT_OPERATION_LEN);
	pos += csmd_dump_buffer(pos, end - pos, "\t\t", bss->ht_operation, HT_OPERATION_LEN);

	if (bss->phy_type == 9) {
		CSMD_CLI_SPRINTF("\tvhtcap[%d]:\n", VHT_CAPABILITY_LEN);
		pos += csmd_dump_buffer(pos, end - pos, "\t\t", bss->vht_capability,
				VHT_CAPABILITY_LEN);
		CSMD_CLI_SPRINTF("\tvhtop[%d]:\n", VHT_OPERATION_LEN);
		pos += csmd_dump_buffer(pos, end - pos, "\t\t", bss->vht_operation,
				VHT_OPERATION_LEN);
	}

	if (check_he_capabilities_ie(bss->he_capability)) {
		CSMD_CLI_SPRINTF("\thecap[%d]:\n", bss->he_capability[1] + 2);
		pos += csmd_dump_buffer(pos, end - pos, "\t\t", bss->he_capability,
			bss->he_capability[1] + 2);
	}
	if (check_he_operation_ie(bss->he_operation)) {
		CSMD_CLI_SPRINTF("\theop[%d]:\n", bss->he_operation[1] + 2);
		pos += csmd_dump_buffer(pos, end - pos, "\t\t", bss->he_operation,
			bss->he_operation[1] + 2);
	}

	pos += csmd_cli_dump_espis(bss, pos, end - pos);

	if (bss->radio)
		CSMD_CLI_SPRINTF("\tradio mac: %" MACFMT "\n", MACARG(bss->radio->h.mac));
	CSMD_CLI_SPRINTF("\toperation_class: %d\n", bss->operation_class);
	if (bss->country_code[0] != '\0')
		CSMD_CLI_SPRINTF("\tcountry code: %c%c\n", bss->country_code[0], bss->country_code[1]);
	CSMD_CLI_SPRINTF("\tfat: %d\n", bss->fat);
	CSMD_CLI_SPRINTF("\tMDID: 0x%02x%02x\n", bss->mdid[0], bss->mdid[1]);
	CSMD_CLI_SPRINTF("\tInternal Used Flags: 0x%08x\n", bss->flag);

_out:
	return pos - buf;
}

static int csmd_cli_dump_sta(void *ctx, stah_t * stah, char *buf, int len)
{
	sta_seen_mdid_t *mdid;
	sta_seen_bssid_t *bssid;
	sta_table_t *sta = (sta_table_t *) stah;
	timestamp_t now = csm_get_timestamp();
	sta_assoc_info_t *assoc = NULL;
	char *pos = buf, *end = buf + len;

	CSMD_CLI_SPRINTF("%" MACFMT "  %2s %2s  %2d %3s  %7d  %5s  ",
		MACARG(sta->h.mac),
		(sta->band_mask & BIT(BAND_2G)) ? "2G" : "",
		(sta->band_mask & BIT(BAND_5G)) ? "5G" : "",
		sta->sta_info.supported_rxss,
		sta->sta_info.supported_capability.vht_supported ?
			((sta->sta_info.supported_capability.vht_bw != 0) ? "160" : "80") :
			(sta->sta_info.supported_capability.ht_bw ? "40" : "20" ),
		csm_get_sta_supported_maxphyrate(sta),
		YESORNO(sta->sta_info.supported_capability.bss_transition_supported));

	if ((sta->flag & (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED))
		== (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED)) {
		assoc = &sta->assoc_info;
		CSMD_CLI_SPRINTF("%" MACFMT "  %02x%02x %4d  %7d %4d/%4d %33d/%d\n",
			MACARG(assoc->assoc_bssid),
			assoc->assoc_mdid[0], assoc->assoc_mdid[1],
			assoc->avg_rssi,
			assoc->supported_phyrate,
			assoc->avg_tx_phyrate, assoc->avg_rx_phyrate,
			csm_get_age(assoc->last_tx_ts), csm_get_age(assoc->last_rx_ts));
	} else {
		CSMD_CLI_SPRINTF("                -     -    -        -    -/   -\n");
	}

	CSM_LOCK(stah);
	list_for_each_entry(mdid, &sta->seen_mdid_lh, lh) {
		list_for_each_entry(bssid, &mdid->seen_bssid_lh, lh) {
			char c = (assoc && MACADDR_EQ(bssid->bssid, assoc->assoc_bssid)) ? '*' : ' ';
			CSMD_CLI_SPRINTF("%104s %02x%02x %" MACFMT "%c %4d %5d  %03u %04u/%03d\n",
				"", mdid->mdid[0], mdid->mdid[1], MACARG(bssid->bssid), c,
				bssid->last_rssi, (int32_t)(now - bssid->last_ts),
				bssid->ch, bssid->ref_phyrate, bssid->ref_rssi);
		}
	}

_out:
	CSM_UNLOCK(stah);
	return (pos - buf);
}

static int csmd_cli_dump_sta_link_stats(sta_table_t *sta, char *buf, int len)
{
	char *pos = buf, *end = buf + len;

	if (sta->node_type == NODE_TYPE_STA
		|| sta->node_type == NODE_TYPE_REPEATER
		|| sta->node_type == NODE_TYPE_WDS
		|| sta->node_type == NODE_TYPE_VAP) {
		CSMD_CLI_SPRINTF("\t\tlink stats:\n");
		CSMD_CLI_SPRINTF("\t\t\t%08u tx_packets\n", sta->assoc_info.stats.tx_packets);
		CSMD_CLI_SPRINTF("\t\t\t%08u tx_bytes\n", sta->assoc_info.stats.tx_bytes);
		CSMD_CLI_SPRINTF("\t\t\t%08u rx_packets\n", sta->assoc_info.stats.rx_packets);
		CSMD_CLI_SPRINTF("\t\t\t%08u rx_bytes\n", sta->assoc_info.stats.rx_bytes);
		CSMD_CLI_SPRINTF("\t\t\t%08u tx_errors\n", sta->assoc_info.stats.tx_errors);
		CSMD_CLI_SPRINTF("\t\t\t%08u rx_errors\n", sta->assoc_info.stats.rx_errors);
		CSMD_CLI_SPRINTF("\t\t\t%08u tx_tries\n", sta->assoc_info.stats.tx_tries);
	}

_out:
	return pos - buf;
}

static int csmd_cli_dump_sta_verbose(void *ctx, stah_t * stah, char *buf, int len)
{
	sta_seen_mdid_t *mdid;
	sta_seen_bssid_t *bssid;
	sta_table_t *sta = (sta_table_t *) stah;
	char *pos = buf, *end = buf + len;

	CSMD_CLI_SPRINTF("Station[%" MACFMT "]: type: %s; refcnt=%d\n", MACARG(sta->h.mac),
		csmd_node_type_to_string(sta->node_type), sta->h.obj.refcnt);

	if (sta->node_type == NODE_TYPE_STA || sta->node_type == NODE_TYPE_REPEATER) {
		CSMD_CLI_SPRINTF("\tlast band[%d]: %" BANDFMT ", last channel: %d\n",
			sta->last_band, BANDARG(sta->last_band), sta->last_channel);
		CSMD_CLI_SPRINTF("\tMax Capability:      %2x\n", sta->sta_info.supported_capability.cap);
		show_capability_details("\t\t", sta->sta_info.supported_capability);
		CSMD_CLI_SPRINTF("\tMax RX streams:      %d\n", sta->sta_info.supported_rxss);
		if (sta->band_mask & BIT(BAND_2G)) {
			CSMD_CLI_SPRINTF("\tsupport: 2.4G\n");
		}
		if (sta->band_mask & BIT(BAND_5G)) {
			CSMD_CLI_SPRINTF("\tsupport: 5G\n");
		}
		CSMD_CLI_SPRINTF("\tBlacklisted: %s", YESORNO(STA_IS_BLACKLISTED(sta)));
		CSMD_CLI_SPRINTF(" MBO: %s", YESORNO(FLAG_IS_SET(sta->flag, STATION_FLAG_MBO)));
		CSMD_CLI_SPRINTF(" OnLegacySlave: %s\n", YESORNO(FLAG_IS_SET(sta->flag, STATION_FLAG_LEGACY1_STA)));
	}
	if ((sta->flag & (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED))
			== (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED)) {
		sta_assoc_info_t *assoc = &sta->assoc_info;
		if (sta->node_type == NODE_TYPE_STA || sta->node_type == NODE_TYPE_REPEATER) {
			CSMD_CLI_SPRINTF("\tAssociation information: with [%" MACFMT
				"], RSSI(dBm): %d(last %d), in MD%02x%02x\n",
				MACARG(assoc->assoc_bssid), assoc->avg_rssi, assoc->last_rssi,
				assoc->assoc_mdid[0], assoc->assoc_mdid[1]);
			CSMD_CLI_SPRINTF("\t\tSupport phyrate: %d\n",
				assoc->supported_phyrate);
			CSMD_CLI_SPRINTF("\t\tAVG phyrate(tx/rx)Mbps: %d/%d\n",
				assoc->avg_tx_phyrate, assoc->avg_rx_phyrate);
			CSMD_CLI_SPRINTF("\t\tLast bandwidth(tx/rx)MHz: %d/%d\n",
				assoc->last_tx_bandwidth, assoc->last_rx_bandwidth);
			CSMD_CLI_SPRINTF("\t\tOperation class IE present: %s\n", YESORNO(assoc->supp_opclass_ie));
			if (assoc->supp_opclass_ie)
				pos += csmd_dump_buffer(pos, end - pos, "\t\t\t", assoc->supp_opclass_ie,
						(*(assoc->supp_opclass_ie + 1)) + 2);
			CSMD_CLI_SPRINTF("\t\tPsk_keyid: %s\n", assoc->psk_keyid);
		} else if (sta->node_type == NODE_TYPE_WDS) {
			CSMD_CLI_SPRINTF("\tAssociation information: with [%" MACFMT
				"], RSSI(dBm): %d\n",
				MACARG(assoc->assoc_bssid), assoc->last_rssi);
			CSMD_CLI_SPRINTF("\t\tAVG phyrate(tx/rx)Mbps: %d/%d\n",
				assoc->avg_tx_phyrate, assoc->avg_rx_phyrate);
		} else if (sta->node_type == NODE_TYPE_NOTWIFI) {
			CSMD_CLI_SPRINTF("\tAssociation information: with [%" MACFMT "]\n",
				MACARG(assoc->assoc_bssid));
			CSMD_CLI_SPRINTF("\t\tFixed phyrate(tx/rx)Mbps: %d/%d\n",
				assoc->avg_tx_phyrate, assoc->avg_rx_phyrate);
		}
	}

	pos += csmd_cli_dump_sta_link_stats(sta, pos, end - pos);

	CSM_LOCK(stah);
	if (sta->node_type == NODE_TYPE_STA || sta->node_type == NODE_TYPE_REPEATER) {
		list_for_each_entry(mdid, &sta->seen_mdid_lh, lh) {
			CSMD_CLI_SPRINTF("\tSeen by MDID %02x%02x\n", mdid->mdid[0],
				mdid->mdid[1]);
			list_for_each_entry(bssid, &mdid->seen_bssid_lh, lh) {
				CSMD_CLI_SPRINTF("\t\tRSSI(dBm) on BSSID[%" MACFMT
					"]: %d, updated %" PRIu64 "\n",
					MACARG(bssid->bssid), bssid->last_rssi,
					bssid->last_ts);
			}
		}
	}
_out:
	CSM_UNLOCK(stah);
	return pos - buf;
}

static inline const char *radio_1905_iftype_string(uint16_t type)
{
	uint16_t ind = type - IFTYPE_1905_11B;
	const char *iftype_strs[] = {
		"11B", "11G", "11A", "11N2G", "11N5G", "11AC", "NA", "11AX2G", "11AX5G"
	};

	if (ind >= ARRAY_SIZE(iftype_strs))
		return "N/A";
	return iftype_strs[ind];
}

static inline char *radio_powerstate_string(uint8_t power)
{
	if (power & CSM_RADIO_POWER_SAVE)
		return "SAVE";
	else
		return "ON";
}

static int csmd_cli_dump_radio(void *ctx, stah_t *stah, char *buf, int len)
{
	radio_table_t *radio = (radio_table_t *)stah;
	char *pos = buf, *end = buf + len;
	int i, j;
	CSMD_CLI_SPRINTF("%" MACFMT " %-5s  %-4s %03u   %03u  %02u      %04u %06u\n",
		MACARG(stah->mac),
		radio_1905_iftype_string(radio->iftype_1905),
		radio_powerstate_string(radio->powerState),
		radio->opclass, radio->chan, radio->maxVAPs,
		radio->fat, csm_get_age(radio->latest_fat_ts));

	for (i = 0; i < radio->opclass_nums; i++) {
		CSMD_CLI_SPRINTF("%67s %03u   %03u %02u ", "",
			radio->opclasses[i].global_opclass,
			radio->opclasses[i].bandwidth,
			radio->opclasses[i].max_txpower);
		for (j = 0; j < radio->opclasses[i].chan_nums; j++)
			CSMD_CLI_SPRINTF(" [%03u:%01x%01x]",
				radio->opclasses[i].chans[j].chan,
				radio->opclasses[i].chans[j].preference,
				radio->opclasses[i].chans[j].reason);
		CSMD_CLI_SPRINTF("\n");
	}
_out:
	return pos - buf;
}

static int csmd_cli_dump_radio_intfs(void *ctx, stah_t *stah, char *buf, int len)
{
	radio_table_t *radio = (radio_table_t *)stah;
	bss_table_t *bss;
	char *pos = buf, *end = buf + len;
	CSMD_CLI_SPRINTF("%" MACFMT " %-5s  %-4s %03u   %03u  %02u      %04u %06u\n",
		MACARG(stah->mac),
		radio_1905_iftype_string(radio->iftype_1905),
		radio_powerstate_string(radio->powerState),
		radio->opclass, radio->chan, radio->maxVAPs,
		radio->fat, csm_get_age(radio->latest_fat_ts));

	list_for_each_entry(bss, &radio->bss_head, radio_lh)
		CSMD_CLI_SPRINTF("%67s %" MACFMT " %-s\n", "",
			MACARG(bss->h.mac), csmd_node_type_to_string(bss->iftype));

_out:
	return pos - buf;
}

static int csmd_cli_dump_devid(void *ctx, stah_t *stah, char *buf, int len)
{
	devid_table_t *devid = (devid_table_t *) stah;
	bss_table_t *bss;
	char *pos = buf, *end = buf + len;
	CSMD_CLI_SPRINTF("%" MACFMT "    %u\n",
			MACARG(devid->h.mac), devid->h.obj.refcnt);

	list_for_each_entry(bss, &devid->bss_lh, lh) {
		CSMD_CLI_SPRINTF("%35s %" MACFMT "\n", "", MACARG(bss->h.mac));
	}
_out:
	return pos - buf;
}

static int csmd_cli_dump_backbone(void *ctx, stah_t *stah, char *buf, int len)
{
	bss_table_t *bss = (bss_table_t *) stah;
	char *pos = buf, *end = buf + len;
	csmctx_t *csm = GET_CSMCTX(ctx);
	sta_table_t *sta = csm_station_find(csm->station_db, bss->backbone_info.uplink_local);
	backbone_type_e type = bss->backbone_info.backbone_type;
	uint32_t phyrate = 1000;
	uint8_t fixed = 1;
	uint8_t peer[ETH_ALEN];
	CLEARMAC(peer);
	if (sta) {
		bss_table_t *next_hop_bss = NULL;
		COPYMAC(peer, sta->assoc_info.assoc_bssid);
		phyrate = sta->assoc_info.avg_tx_phyrate;
		if (type == BACKBONE_TYPE_NONE &&
			(sta->node_type == NODE_TYPE_WDS
			|| sta->node_type == NODE_TYPE_STA
			|| sta->node_type == NODE_TYPE_REPEATER)) {
			next_hop_bss = (bss_table_t *)stadb_sta_find_unlock(csm->bss_db, sta->assoc_info.assoc_bssid);
			if(next_hop_bss && next_hop_bss->channel == bss->channel)
				type = BACKBONE_TYPE_SHARED;
			else
				type = BACKBONE_TYPE_INDEPENDENT;
			if(next_hop_bss)
				csm_put(next_hop_bss);
		}
		if (sta->node_type != NODE_TYPE_NOTWIFI)
			fixed = 0;
		csm_put(sta);
	}

	if (type == BACKBONE_TYPE_NONE)
		CSMD_CLI_SPRINTF("%" MACFMT "    %6s        --   --:--:--:--:--:--   --:--:--:--:--:--      --Mbps\n",
				MACARG(bss->h.mac), "none");
	else
		CSMD_CLI_SPRINTF("%" MACFMT "    %6s     %5s   %" MACFMT "   %" MACFMT "   %5uMbps\n",
				MACARG(bss->h.mac), type == BACKBONE_TYPE_INDEPENDENT ? "indep" : "shared",
				fixed ? "fixed" : "auto", MACARG(bss->backbone_info.uplink_local),
				MACARG(peer), phyrate);
_out:
	return pos - buf;
}

static char *g_buf = NULL;
static uint32_t g_buf_size = 0;
static void csmd_cli_realloc_buf(void)
{
	if (g_buf)
		CSM_FREE(g_buf);
	g_buf_size += MAX_CTRL_MSG_LEN;
	g_buf = CSM_CALLOC(1, g_buf_size);
}

static void csmd_cli_reset_buf(void)
{
	if (g_buf)
		CSM_FREE(g_buf);
	g_buf = NULL;
	g_buf_size = 0;
}

static void csmd_cli_sendto_client(struct csmd_cli *cli, char *rep, uint32_t len,
	uint8_t more, struct sockaddr_un addr, socklen_t addr_len)
{
	rep = VALID_CTRL_MSG_HEAD(rep);
	len = VALID_CTRL_MSG_LEN(len);
	do {
		uint32_t send_len = MAX_VALID_CTRL_MSG_LEN;
		if (len < MAX_VALID_CTRL_MSG_LEN)
			send_len = len;

		*(rep - RESERVE_LEN) = more;
		if (sendto(cli->ctrl_sock, rep - RESERVE_LEN, send_len + RESERVE_LEN, 0,
			(struct sockaddr *) &addr, addr_len) < 0) {
			CSM_WARNING(PPREFIX
				"Failed to send frame to ctrl socket: %s\n",
				strerror(errno));
			return;
		}
		rep += send_len;
		len -= send_len;
	} while (len);
}

static void csmd_cli_dump_entry_index(struct csmd_cli *cli, int index,
	struct sockaddr_un addr, socklen_t addr_len)
{
	char *pos = VALID_CTRL_MSG_HEAD(rep), *end = rep + sizeof(rep);
	memset(rep, 0, sizeof(rep));
	pos += snprintf(pos, end - pos, "%04u. ", index);
	csmd_cli_sendto_client(cli, rep, pos - rep, CTRL_MSG_MORE, addr, addr_len);
}

static void csmd_cli_dump_header(struct csmd_cli *cli, const char *header,
	struct sockaddr_un addr, socklen_t addr_len)
{
	if(header) {
		char *pos = VALID_CTRL_MSG_HEAD(rep), *end = rep + sizeof(rep);
		memset(rep, 0, sizeof(rep));
		pos += snprintf(pos, end - pos, "%s", header);
		csmd_cli_sendto_client(cli, rep, pos - rep, CTRL_MSG_MORE, addr, addr_len);
	}
}

static void csmd_cli_dump_deal_one_entry(struct csmd_cli *cli, stah_t *stah,
	table_show_func_t show, int index,
	struct sockaddr_un addr, socklen_t addr_len)
{
	uint32_t size;
	csmd_cli_dump_entry_index(cli, index, addr, addr_len);
	while(1) {
		char *pos = VALID_CTRL_MSG_HEAD(g_buf), *end = g_buf + g_buf_size;
		if (!g_buf || !g_buf_size)
			return;
		memset(g_buf, 0, g_buf_size);
		size = show(cli->csm_ctx, stah, pos, end - pos);
		if (size < end - pos)
			break;
		csmd_cli_realloc_buf();
	}

	csmd_cli_sendto_client(cli, g_buf, size + 1, CTRL_MSG_MORE, addr, addr_len);
}

static void csmd_cli_dump_tailer(struct csmd_cli *cli, const char *tailer,
	int index, int sizes,
	struct sockaddr_un addr, socklen_t addr_len)
{
	char *pos = VALID_CTRL_MSG_HEAD(rep), *end = rep + sizeof(rep);
	memset(rep, 0, sizeof(rep));
	pos += snprintf(pos, end - pos, "%sTotal table entries: %d of %d\n",
		tailer ? tailer : "", index, sizes);
	csmd_cli_sendto_client(cli, rep, pos - rep, CTRL_MSG_END, addr, addr_len);
}

static void csmd_cli_dump_table_to_client(struct csmd_cli *cli, struct sta_sdb *db,
	table_filter_func_t filter, void *filter_data1, void *filter_data2,
	table_show_func_t show, const char *header,
	struct sockaddr_un addr, socklen_t addr_len)
{
	int i, j = 0;

	csmd_cli_dump_header(cli, header, addr, addr_len);

	csmd_cli_realloc_buf();
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah;
		struct list_head *l;
		l = &db->stalh[i];
		list_for_each_entry(stah, l, lh) {
			if (filter(stah, filter_data1, filter_data2))
				csmd_cli_dump_deal_one_entry(cli, stah,
					show, ++j, addr, addr_len);
		}
	}
	csmd_cli_reset_buf();

	csmd_cli_dump_tailer(cli, NULL, j, db->size, addr, addr_len);
}

static void csmd_cli_dump_list_to_client(struct csmd_cli *cli, stah_t **stalist,
	table_filter_func_t filter, void *filter_data1, void *filter_data2,
	table_show_func_t show, const char *header,
	struct sockaddr_un addr, socklen_t addr_len)
{
	int j = 0, k = 0;

	csmd_cli_dump_header(cli, header, addr, addr_len);

	csmd_cli_realloc_buf();
	while (*stalist){
		stah_t *stah = *stalist;
		k++;
		if (filter(stah, filter_data1, filter_data2))
			csmd_cli_dump_deal_one_entry(cli, stah,
				show, ++j, addr, addr_len);
		stalist++;
	}
	csmd_cli_reset_buf();

	csmd_cli_dump_tailer(cli, NULL, j, k, addr, addr_len);
}

static int csmd_cli_handle_show_sta_req(struct csmd_cli *cli, int argc, char *argv[],
	struct sockaddr_un addr, socklen_t addr_len)
{
	uint8_t mac[ETH_ALEN];
	table_filter_func_t filter = csmd_debug_filter_all;
	struct sta_sdb *db;
	int verbose = 0;

	if (argc == 0 || MATCH("all", argv[0])) {
		filter = csmd_debug_filter_all;
	} else if (MATCH("verbose", argv[0])) {
		filter = csmd_debug_filter_all;
		verbose = 1;
	} else if (MATCH("assoc", argv[0])) {
		filter = csmd_debug_station_filter_associated_station;
	} else if (MATCH("nassoc", argv[0])) {
		filter = csmd_debug_station_filter_non_associated_station;
	} else if (MATCH("bl", argv[0])) {
		filter = csmd_debug_station_filter_blacklist_station;
	} else if (ether_aton_r(argv[0], (struct ether_addr *) mac)) {
		filter = csmd_debug_station_filter_with_mac;
	} else {
		return -1;
	}

	if(argc >= 2 && MATCH("verbose", argv[1]))
		verbose = 1;

	db = csm_get_station_table_snapshot(cli->csm_ctx);
	if(verbose)
		csmd_cli_dump_table_to_client(cli, db, filter, mac, NULL, csmd_cli_dump_sta_verbose,
			NULL, addr, addr_len);
	else
		csmd_cli_dump_table_to_client(cli, db, filter, mac, NULL, csmd_cli_dump_sta,
			STA_TABLE_HEADER, addr, addr_len);
	csm_put_station_table_snapshot(db);

	return 0;
}

static int csmd_cli_handle_show_bss_req(struct csmd_cli *cli, int argc, char *argv[],
	struct sockaddr_un addr, socklen_t addr_len)
{
	table_filter_func_t filter = csmd_debug_filter_all;
	struct sta_sdb *db;
	int verbose = 0;

	if (argc == 0 || MATCH("all", argv[0])) {
		filter = csmd_debug_filter_all;
	} else if (MATCH("verbose", argv[0])) {
		filter = csmd_debug_filter_all;
		verbose = 1;
	} else {
		return -1;
	}

	if(argc >= 2 && MATCH("verbose", argv[1]))
		verbose = 1;

	db = csm_get_bss_table_snapshot(cli->csm_ctx);
	if(verbose)
		csmd_cli_dump_table_to_client(cli, db, filter, NULL, NULL, csmd_cli_dump_bss_verbose,
			NULL, addr, addr_len);
	else
		csmd_cli_dump_table_to_client(cli, db, filter, NULL, NULL, csmd_cli_dump_bss,
			BSS_TABLE_HEADER, addr, addr_len);
	csm_put_bss_table_snapshot(db);

	return 0;
}

static int csmd_cli_handle_show_radio_req(struct csmd_cli *cli, int argc, char *argv[],
	struct sockaddr_un addr, socklen_t addr_len)
{
	int intfs = 0;
	struct sta_sdb *db = csm_get_radio_table(cli->csm_ctx);

	if (argc > 0 && MATCH("intfs", argv[0]))
		intfs = 1;

	if (!intfs)
		csmd_cli_dump_table_to_client(cli, db, csmd_debug_filter_all, NULL, NULL,
			csmd_cli_dump_radio, RADIO_TABLE_HEADER, addr, addr_len);
	else
		csmd_cli_dump_table_to_client(cli, db, csmd_debug_filter_all, NULL, NULL,
			csmd_cli_dump_radio_intfs, RADIO_TABLE_INTF_HEADER, addr, addr_len);

	csm_put_radio_table(db);
	return 0;
}

static int csmd_cli_handle_show_devid_req(struct csmd_cli *cli,
	struct sockaddr_un addr, socklen_t addr_len)
{
	table_filter_func_t filter = csmd_debug_filter_all;
	struct sta_sdb *db;
	db = csm_get_devid_table(cli->csm_ctx);
	csmd_cli_dump_table_to_client(cli, db, filter, NULL, NULL, csmd_cli_dump_devid,
		DEVID_TABLE_HEADER, addr, addr_len);
	csm_put_devid_table(db);
	return 0;
}

static int csmd_cli_handle_show_backbone_req(struct csmd_cli *cli,
	struct sockaddr_un addr, socklen_t addr_len)
{
	table_filter_func_t filter = csmd_debug_filter_all;
	bss_table_t **bss_list = NULL;

	bss_list = csm_bss_list_get_by_filter(cli->csm_ctx, filter, NULL, NULL);
	csmd_cli_dump_list_to_client(cli, (stah_t **)bss_list, filter, NULL, NULL, csmd_cli_dump_backbone,
		BACKBONE_TABLE_HEADER, addr, addr_len);
	csm_bss_list_put(bss_list);
	return 0;
}

static int csmd_cli_handle_show_req(struct csmd_cli *cli, int argc, char *argv[],
	struct sockaddr_un addr, socklen_t addr_len)
{
	if (argc < 1)
		return -1;

	if (MATCH("sta", argv[0]))
		return csmd_cli_handle_show_sta_req(cli, argc - 1, argv + 1, addr, addr_len);
	else if (MATCH("bss", argv[0]))
		return csmd_cli_handle_show_bss_req(cli, argc - 1, argv + 1, addr, addr_len);
	else if (MATCH("radio", argv[0]))
		return csmd_cli_handle_show_radio_req(cli, argc - 1, argv + 1, addr, addr_len);
	else if (MATCH("devid", argv[0]))
		return csmd_cli_handle_show_devid_req(cli, addr, addr_len);
	else if (MATCH("backbone", argv[0]))
		return csmd_cli_handle_show_backbone_req(cli, addr, addr_len);
	else
		return -1;
}

static int csmd_cli_handle_dbg_req(struct csmd_cli *cli, int argc, char *argv[],
	char *rep, int rep_len)
{
	int ret = -1;
	if (argc == 0 || MATCH("show", argv[0])) {
		return csm_log_settings_show(rep, rep_len);
	} else if (MATCH("level", argv[0])) {
		if (argc <= 2) {
			ret = CSM_SET_DEBUG_LEVEL(argv[1]);
		} else {
			ret = csm_log_set_level(argv[1], argv[2]);
		}
	} else if (MATCH("output", argv[0])
		&& argc >= 2) {
		ret = csm_log_set_output(argv[1]);
	}
#ifdef MEMORY_DEBUG
	else if (MATCH("memory", argv[0])) {
		if (MATCH("history", argv[1]))
			csm_debug_memory_dump(1);
		else if (MATCH("increase", argv[1]))
			csm_debug_memory_dump(2);
		else
			csm_debug_memory_dump(0);
		ret = 0;
	}
#endif
	if (0 != ret)
		return csmd_cli_help(cli, rep, rep_len);

	return sprintf(rep, "successful\n");
}

static int  csmd_cli_erw_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage: csmd_cli cmd erw <params>\n"
		"	cmd erw <help>				: help for erw test command\n"
		"	cmd erw <bssid> add <MAC> [<rssi_min/rssi_max/none>] [<mask>] [<rssi>] [<code>] [<payload>]\n"
		"	cmd erw <bssid> del <MAC>\n"
		"	cmd erw <bssid> clr_nr <min>[-<max>]\n"
		"	cmd erw <bssid> <file_name>		: operate the erw from file\n"
		"		format of file:\n"
		"			OP; STA; MODE; MASK; RSSI; CODE; PAYLOAD;\n"
		"			#OP can be + for add, - for del, ~ for clr neigh report\n"
		"			#STA is mac address\n"
		"			#MODE can be rssi_min, rssi_max and none\n"
		"			#MASK indicate which frame do not need to check withholding, hex format\n"
		"			#CODE indicate reject mode\n"
		"			#PAYLOAD is the neigh report if the CODE is 82\n"
		"		example of file:\n"
		"			+; 00:12:34:56:78:00; rssi_min; 00; -60;\n"
		"			+; 00:12:34:56:78:01; rssi_max; 01; -30; 82; 100204000000000034000d0000123456789000000000000a0c000000;\n"
		"			+; 00:12:34:56:78:02; none; 02;\n"
		"			-; 00:12:34:56:78:03;\n"
		"			-; 00:00:00:00:00:00;\n"
		"			+; FF:FF:FF:FF:FF:FF; rssi_min; 00; -60; 1;\n"
		"			~; 0-8;\n"
		"\n");
}

static csm_erw_list_t g_erws;
static void csmd_fill_one_erw_entry(uint32_t ind, uint8_t *sta,
	uint8_t action, uint8_t mode, int8_t rssi, uint8_t mask,
	uint16_t reject_mode, uint16_t reject_payload_len, uint8_t *reject_payload)
{
	COPYMAC(g_erws.entries[ind].sta, sta);
	g_erws.entries[ind].action = action;
	g_erws.entries[ind].rssi_mode = mode;
	g_erws.entries[ind].rssi = rssi;
	g_erws.entries[ind].mask = mask;
	g_erws.entries[ind].reject_mode = reject_mode;
	g_erws.entries[ind].reject_payload_len = reject_payload_len;
	g_erws.entries[ind].reject_payload = reject_payload;
}

static void csmd_erw_free(csm_erw_list_t *erws)
{
	uint32_t nums, i;

	nums = erws->nums;
	if (nums > CSM_MAX_ERW_ENTRIES)
		nums = CSM_MAX_ERW_ENTRIES;

	for (i = 0; i < nums; i++) {
		if (erws->entries[i].reject_payload) {
			CSM_FREE(erws->entries[i].reject_payload);
			erws->entries[i].reject_payload = NULL;
		}
	}
}

static int csmd_erw_set(struct csmd_cli *cli, uint8_t *bssid, csm_erw_list_t *erws)
{
	int ret;

	ret = csm_set_erw(cli->csm_ctx, bssid, erws);
	csmd_erw_free(erws);

	return ret;
}

static uint32_t csmd_get_string_payload(char *str, uint8_t **payload)
{
	uint32_t len = strlen(str), hexs_len, i;
	uint8_t *hexs;
	while ((str[len -1] < '0' || str[len - 1] > '9')
		&& (str[len - 1] < 'a' || str[len - 1] > 'f')
		&& (str[len - 1] < 'A' || str[len - 1] > 'F'))
		len--;
	hexs_len = len / 2;
	if (len % 2) {
		CSM_WARNING(PPREFIX "payload sting for len(%u) is not multiple of 2", len);
		return 0;
	}
	hexs = CSM_MALLOC(len / 2);
	if (!hexs)
		return 0;
	for (i = hexs_len; i > 0; i--) {
		*(hexs + i - 1) = strtoul(str + (i - 1) * 2, NULL, 16);
		*(str + (i - 1) * 2) = '\0';
	}
	*payload = hexs;
	return hexs_len;
}

static uint32_t csmd_erw_get_clr_nr_payload(char *str, uint8_t **payload)
{
	uint16_t min, max, i;
	uint16_t tlv_len = sizeof(tlv_t) + csm_tlv_vlen(TLVTYPE_NRIE_INDEX);
	uint8_t *nries, *pos;
	uint8_t tmp[4];
	char *substr = NULL;

	min = max = atoi(str);
	if (NULL != (substr = strchr(str, '-'))
		&& *(++substr) != '\0')
		max = atoi(substr);

	if (max < min)
		return 0;
	nries = CSM_MALLOC((max - min + 1) * tlv_len);
	if (!nries)
		return 0;
	memset(tmp, 0, 4);
	pos = nries;
	for (i = min; i <= max; i++) {
		*(uint16_t *)tmp = host_to_le16(i);
		pos += csm_encap_tlv(pos, TLVTYPE_NRIE_INDEX, tmp, 4);
	}
	*payload = nries;
	return (pos - nries);
}

static int csmd_erw_add(struct csmd_cli *cli, uint8_t *bssid, int argc, char *argv[],
	char *rep, int rep_len)
{
	uint8_t sta[ETH_ALEN];
	uint8_t mode = CSM_ERW_RSSI_MODE_NONE;
	int8_t rssi = 0;
	uint8_t mask = 0xff;
	uint16_t code = 0, payload_len = 0;
	uint8_t *payload = NULL;

	if (argc < 2)
		return csmd_cli_erw_help(cli, rep, rep_len);

	if (NULL == ether_aton_r(argv[0], (struct ether_addr *)sta))
		return csmd_cli_help(cli, rep, rep_len);
	if (MATCH("rssi_min", argv[1]))
		mode = CSM_ERW_RSSI_MODE_MIN;
	else if (MATCH("rssi_max", argv[1]))
		mode = CSM_ERW_RSSI_MODE_MAX;

	if (argc >= 3)
		mask = strtoul(argv[2], NULL, 16);
	if (argc >= 4)
		rssi = atoi(argv[3]);
	if (argc >= 5)
		code = atoi(argv[4]);
	if (code == REJECT_WITH_NRIE && argc >= 6)
		payload_len = csmd_get_string_payload(argv[5], &payload);

	g_erws.nums = 1;
	csmd_fill_one_erw_entry(0, sta, CSM_ERW_ACTION_ADD, mode,
		rssi, mask, code, payload_len, payload);

	if (csmd_erw_set(cli, bssid, &g_erws) < 0)
		return sprintf(rep, "fail\n");
	return sprintf(rep, "successful\n");
}

static int csmd_erw_del(struct csmd_cli *cli, uint8_t *bssid, int argc, char *argv[],
	char *rep, int rep_len)
{
	uint8_t sta[ETH_ALEN];

	if (argc < 1)
		return csmd_cli_erw_help(cli, rep, rep_len);

	if (NULL == ether_aton_r(argv[0], (struct ether_addr *)sta))
		return csmd_cli_help(cli, rep, rep_len);

	g_erws.nums = 1;
	csmd_fill_one_erw_entry(0, sta, CSM_ERW_ACTION_DEL, 0, 0, 0, 0, 0, NULL);

	if (csmd_erw_set(cli, bssid, &g_erws) < 0)
		return sprintf(rep, "fail\n");
	return sprintf(rep, "successful\n");
}

static int csmd_erw_clr_nr(struct csmd_cli *cli, uint8_t *bssid, int argc, char *argv[],
	char *rep, int rep_len)
{
	uint16_t payload_len = 0;
	uint8_t *payload = NULL;
	uint8_t bc[ETH_ALEN] = "\xff\xff\xff\xff\xff\xff";
	if (argc < 1)
		return csmd_cli_erw_help(cli, rep, rep_len);

	payload_len = csmd_erw_get_clr_nr_payload(argv[0], &payload);
	g_erws.nums = 1;
	csmd_fill_one_erw_entry(0, bc, CSM_ERW_ACTION_CLR_NR, 0, 0, 0, 0, payload_len, payload);

	if (csmd_erw_set(cli, bssid, &g_erws) < 0)
		return sprintf(rep, "fail\n");
	return sprintf(rep, "successful\n");
}

#define ERW_PARSE_NEXT_PARAM() do { p = substr;\
		if (!p) goto __deal_erw;	\
		if(NULL == (substr = strchr(p, ';'))) break;\
		*substr = '\0';\
		substr++;\
		while(isspace(*substr)) ++substr;\
	} while(0)

static int csmd_erw_update_from_file(struct csmd_cli *cli, uint8_t *bssid, int argc, char *argv[],
	char *rep, int rep_len)
{
	FILE *fd;
	char *line = NULL;
	size_t len = 0;

	if (argc < 1)
		return csmd_cli_erw_help(cli, rep, rep_len);

	fd = fopen(argv[0], "r");
	if (fd == NULL)
		return sprintf(rep, "open file %s is error: %s\n", argv[0], strerror(errno));

	g_erws.nums = 0;
	while(getline(&line, &len, fd) > 0) {
		char *p;
		char *substr = line;
		uint8_t action, mode = CSM_ERW_RSSI_MODE_NONE, mask = 0, rssi = 0;
		uint16_t code = 0, payload_len = 0;
		uint8_t *payload = NULL;
		uint8_t sta[ETH_ALEN];

		while(isspace(*substr))
			++substr;
		if(*substr == '\0'
			|| *substr == '#')
			continue;

		ERW_PARSE_NEXT_PARAM();
		if (*p == '+')
			action = CSM_ERW_ACTION_ADD;
		else if (*p == '-')
			action = CSM_ERW_ACTION_DEL;
		else if (*p == '~')
			action = CSM_ERW_ACTION_CLR_NR;
		else
			continue;

		if (action == CSM_ERW_ACTION_CLR_NR) {
			memset(sta, 0xff, ETH_ALEN);
			payload_len = csmd_erw_get_clr_nr_payload(substr, &payload);
			goto __deal_erw;
		}

		ERW_PARSE_NEXT_PARAM();
		if (NULL == ether_aton_r(p, (struct ether_addr *)sta))
			continue;

		if (action == CSM_ERW_ACTION_ADD) {
			ERW_PARSE_NEXT_PARAM();
			if (MATCH("rssi_min", p))
				mode = CSM_ERW_RSSI_MODE_MIN;
			else if (MATCH("rssi_max", p))
				mode = CSM_ERW_RSSI_MODE_MAX;
			ERW_PARSE_NEXT_PARAM();
			mask = strtoul(p, NULL, 16);
			ERW_PARSE_NEXT_PARAM();
			rssi = atoi(p);
			ERW_PARSE_NEXT_PARAM();
			code = atoi(p);
			ERW_PARSE_NEXT_PARAM();
			if (code == REJECT_WITH_NRIE)
				payload_len = csmd_get_string_payload(p, &payload);
		}

__deal_erw:
		if (g_erws.nums >= CSM_MAX_ERW_ENTRIES) {
			csmd_erw_set(cli, bssid, &g_erws);
			g_erws.nums = 0;
		}
		csmd_fill_one_erw_entry(g_erws.nums, sta, action, mode,
			rssi, mask, code, payload_len, payload);
		g_erws.nums++;
	}
	if (line)
		free(line);
	fclose(fd);

	if (g_erws.nums)
		csmd_erw_set(cli, bssid, &g_erws);

	return sprintf(rep, "req %u successful\n", g_erws.nums);
}

static int csmd_cli_mbo_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage csmd_cli cmd mbo <params>\n"
		" 	cmd mbo <help> 			: help for mbo test command\n"
		" 	cmd mbo <bssid> reg_frame <tx/rx> <subtype> <drv_process> [match]\n"
		" 			- subtype:0x00 0x20 0x40 0xa0 0xb0 0xc0 0xd0\n"
		" 			- drv_process: skb_copy(0) bypass(1)\n"
		" 			- match:040a 040c 0501 0504 0a06 0a08 0a1a\n"
		" 	cmd mbo <bssid> update_ies <subtype> <ies> <ies_len>\n"
		" 			- ELEMID [RM:0x46|INTERWORKING:0x68|ADVER:0x69|VENDOR:0xdd]\n"
		" 			- subtype beacon:0x80 probe rsp:0x50 assoc rsp:0x10\n"
		" 	cmd mbo <bssid> update_extcap <extcap> <extcap_mask> <extcap_len>\n"
		" 			- BIT(19) : BSS Transition  -\n"
		" 			- BIT(31) : Interworking    -\n"
		" 			- BIT(46) : WNM notification-\n"
		" 	cmd mbo <bssid> update_3rd_cc <val>\n"
		" 			- 3rd of country element in beacon/probe resp 0x20/0x04\n"
		" 	cmd mbo <bssid> send_frame <channel> <frame>\n"
		" 			- frame: a string of hex format that include mac header\n"
		"\n");
}

static int csmd_mbo_reg_frame(struct csmd_cli *cli, uint8_t *bssid,
	int argc, char *argv[], char *rep, int rep_len)
{
	uint8_t subtype = 0xff;
	uint8_t *match = NULL;
	uint8_t txrx, drv_process = 0;
	uint8_t match_len = 0;

	if (argc < 3)
		return csmd_cli_mbo_help(cli, rep, rep_len);

	if (MATCH("tx", argv[0]))
		txrx = 1;
	else
		txrx = 0;
	subtype = strtoul(argv[1], NULL, 16);
	drv_process = strtoul(argv[2], NULL, 10);
	if (argc >= 4)
		match_len = csmd_get_string_payload(argv[3], &match);

	if (csm_mbo_reg_frm_cmd(cli->csm_ctx, bssid,
		txrx, subtype, drv_process, match_len, match) < 0) {
		if (match)
			CSM_FREE(match);
		return sprintf(rep, "failed\n");
	}

	if (match)
		CSM_FREE(match);

	return sprintf(rep, "successful\n");
}

static int csmd_mbo_update_ies(struct csmd_cli *cli, uint8_t *bssid,
	int argc, char *argv[], char *rep, int rep_len)
{
	return sprintf(rep, "successful\n");
}

static int csmd_mbo_update_extcap(struct csmd_cli *cli, uint8_t *bssid,
	int argc, char *argv[], char *rep, int rep_len)
{
	return sprintf(rep, "successful\n");
}

static int csmd_mbo_update_3rd_cc(struct csmd_cli *cli, uint8_t *bssid,
	int argc, char *argv[], char *rep, int rep_len)
{
	return sprintf(rep, "successful\n");
}

static int csmd_mbo_send_frame(struct csmd_cli *cli, uint8_t *bssid,
	int argc, char *argv[], char *rep, int rep_len)
{
#define IEEE80211_FRAME_MIN_LEN 24
	uint8_t channel;
	uint8_t *frm = NULL;
	uint16_t frm_len;

	if (argc < 2)
		return csmd_cli_mbo_help(cli, rep, rep_len);

	channel = strtoul(argv[0], NULL, 10);
	frm_len = csmd_get_string_payload(argv[1], &frm);
	if (frm_len <= IEEE80211_FRAME_MIN_LEN) {
		CSM_ERROR("set send frame must include mac header + frame body");
		if (frm)
			CSM_FREE(frm);
		return sprintf(rep, "failed\n");
	}
	if (csm_mbo_send_frame_cmd(cli->csm_ctx, bssid,
		channel, frm_len, frm) < 0) {
		if (frm)
			CSM_FREE(frm);
		return sprintf(rep, "failed\n");
	}

	if (frm)
		CSM_FREE(frm);

	return sprintf(rep, "successful\n");
}

static int csmd_cli_seen_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage csmd_cli cmd seen <sta> del/add [<bss>] [<rssi>]\n");
}

static int csmd_seen_del(struct csmd_cli *cli, uint8_t *mac,
	int argc, char *argv[], char *rep, int rep_len)
{
	uint8_t bssid[ETH_ALEN];
	csmctx_t *csm;
	sta_table_t *sta;

	if (argc > 0 && (NULL == ether_aton_r(argv[0], (struct ether_addr *)bssid)))
		return csmd_cli_seen_help(cli, rep, rep_len);

	if (!cli->csm_ctx)
		return snprintf(rep, rep_len, "failed: csm context is null\n");

	csm = GET_CSMCTX(cli->csm_ctx);
	sta = csm_station_find(csm->station_db, mac);
	if (!sta)
		return snprintf(rep, rep_len, "failed: %" MACFMT " does not exist\n", MACARG(mac));

	CSM_LOCK(sta);
	csm_seen_bssid_del(sta, argc > 0 ? bssid : NULL);
	CSM_UNLOCK(sta);

	csm_station_put(sta);

	return sprintf(rep, "successful\n");
}

static int csmd_seen_add(struct csmd_cli *cli, uint8_t *mac,
	int argc, char *argv[], char *rep, int rep_len)
{
	uint8_t bssid[ETH_ALEN];
	csmctx_t *csm;
	sta_table_t *sta;
	sta_seen_bssid_t *seen;
	struct sta_sdb *db = NULL;
	rssi_t rssi = 0;
	int i;

	if (argc <= 0 || (NULL == ether_aton_r(argv[0], (struct ether_addr *)bssid)))
		return csmd_cli_seen_help(cli, rep, rep_len);
	if (argc > 1)
		rssi = atoi(argv[1]);

	if (!cli->csm_ctx)
		return snprintf(rep, rep_len, "failed: csm context is null\n");

	csm = GET_CSMCTX(cli->csm_ctx);
	sta = csm_station_find(csm->station_db, mac);
	if (!sta)
		return snprintf(rep, rep_len, "failed: sta %"
			MACFMT " does not exist\n", MACARG(mac));

	db = csm_get_bss_table(cli->csm_ctx);
	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		struct list_head *head = &db->stalh[i];
		stah_t *stah;
		list_for_each_entry(stah, head, lh) {
			if (MACEQUAL(bssid, "\xff\xff\xff\xff\xff\xff")
				|| MACEQUAL(bssid, stah->mac)) {
				bss_table_t *bss = (bss_table_t *)stah;
				if (bss->flag & BSS_FLAG_DOWN)
					continue;

				CSM_LOCK(sta);
				seen = csm_seen_bssid_find_or_add(sta, bss->mdid, bss->h.mac);
				if (seen) {
					if (rssi)
						seen->last_rssi = rssi;
					else if (!seen->last_rssi)
						seen->last_rssi = -50;
					seen->last_ts = csm_get_timestamp();
				}
				CSM_UNLOCK(sta);
			}
		}
	}
	CSM_UNLOCK(db);

	csm_station_put(sta);

	return sprintf(rep, "successful\n");
}

static int csmd_cli_set_chan_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage csmd_cli cmd set_chan <radio> [opclass] [chan] [<txpower>] [<bandwidth>]\n");
}

static int csmd_cli_set_chan(struct csmd_cli *cli, uint8_t *rmac,
	int argc, char *argv[], char *rep, int rep_len)
{
	uint8_t txpower = 18, bw = 0, opcls, ch;
	if (argc < 2)
		return csmd_cli_set_chan_help(cli, rep, rep_len);

	opcls = atoi(argv[0]);
	ch = atoi(argv[1]);
	if (argc >= 3)
		txpower = atoi(argv[2]);
	if (argc >= 4)
		bw = atoi(argv[3]);

	if (csm_set_radio_channel(cli->csm_ctx, rmac, opcls, ch, txpower, bw) < 0)
		return sprintf(rep, "fail\n");
	return sprintf(rep, "successful\n");
}

static int csmd_cli_set_intf_cfg_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage csmd_cli cmd set_intf_cfg <bssid> [feat] [mask] [<param=val>]"
			"param: mon_period, mon_percent/mon_on/nac_chan,interworking/an_type/hessid\n");
}

static int csmd_cli_set_intf_cfg(struct csmd_cli *cli, uint8_t *bssid,
	int argc, char *argv[], char *rep, int rep_len)
{
	csm_intf_cfg_t cfg;
	int i;

	if (argc < 2)
		return csmd_cli_set_intf_cfg_help(cli, rep, rep_len);

	memset(&cfg, 0, sizeof(cfg));

	cfg.feat = strtoul(argv[0], NULL, 0);
	cfg.feat_mask = strtoul(argv[1], NULL, 0);
	for (i = 2; i < argc && i < 16; i++) {
		char *key = argv[i];
		char *value = strchr(key, '=');
		if (!value)
			return csmd_cli_set_intf_cfg_help(cli, rep, rep_len);
		*value++ = '\0';

		if (strcmp("mon_period", key) == 0) {
			cfg.mon_param.period = atoi(value);
		} else if (strcmp("mon_percent", key) == 0) {
			cfg.mon_param.on_period = atoi(value);
			cfg.mon_param.percent = 1;
		} else if (strcmp("mon_on", key) == 0) {
			cfg.mon_param.on_period = atoi(value);
			cfg.mon_param.percent = 0;
		} else if (strcmp("nac_chan", key) == 0) {
			cfg.mon_param.nac_chan = atoi(value);
		} else if (strcmp("interworking", key) == 0) {
			cfg.interw_param.interw_en = atoi(value);
		} else if (strcmp("an_type", key) == 0) {
			cfg.interw_param.an_type = atoi(value);
		} else if (strcmp("hessid", key) == 0) {
			if(NULL == ether_aton_r(value, (struct ether_addr *) cfg.interw_param.hessid))
				return csmd_cli_set_intf_cfg_help(cli, rep, rep_len);
		}
	}

	if (csm_set_intf_cfg(cli->csm_ctx, bssid, &cfg) < 0)
		return sprintf(rep, "fail\n");
	return sprintf(rep, "successful\n");
}

static int csmd_cli_roam_help(struct csmd_cli *cli, char *rep, int rep_len)
{
	return snprintf(rep, rep_len,
		"Usage csmd_cli cmd roam <mac> <target> <chan> <opclass>\n");
}

static int csmd_cli_roam(struct csmd_cli *cli, uint8_t *sta, uint8_t *target,
	int argc, char *argv[], char *rep, int rep_len)
{
	uint8_t chan = 0, opclass = 0;
	if (argc < 2)
		return csmd_cli_roam_help(cli, rep, rep_len);

	chan = atoi(argv[0]);
	opclass = atoi(argv[1]);

	if (csm_sta_roam(cli->csm_ctx, sta, target, chan, opclass) < 0)
		return sprintf(rep, "fail\n");
	return sprintf(rep, "successful\n");
}

static int csmd_cli_handle_cmd_req(struct csmd_cli *cli, int argc, char *argv[],
	char *rep, int rep_len)
{
	if (argc < 1)
		return csmd_cli_help(cli, rep, rep_len);

	if (MATCH("deauth_and_blacklist", argv[0])
		|| MATCH("black", argv[0])) {
		uint8_t bssid[ETH_ALEN];
		uint8_t sta[ETH_ALEN];
		uint16_t code, blacklist;
		if(argc < 5)
			return csmd_cli_help(cli, rep, rep_len);
		if(NULL == ether_aton_r(argv[2], (struct ether_addr *) bssid))
			return csmd_cli_help(cli, rep, rep_len);
		if(NULL == ether_aton_r(argv[1], (struct ether_addr *) sta))
			return csmd_cli_help(cli, rep, rep_len);
		code = atoi(argv[3]);
		blacklist = atoi(argv[4]);

		printf("deauth and blacklist %" MACFMT
			" from BSS[%" MACFMT
			" code=%d blacklist=%d\n", MACARG(sta),
			MACARG(bssid), code, blacklist);
		csm_deauth_and_blacklist_sta(cli->csm_ctx, bssid,
			sta, code, blacklist);
	} else if (MATCH("bss_trans", argv[0])
		|| MATCH("11v", argv[0])) {
		uint8_t bssid_dst[ETH_ALEN];
		uint8_t sta[ETH_ALEN];

		if(NULL == ether_aton_r(argv[1], (struct ether_addr *) sta))
			return csmd_cli_help(cli, rep, rep_len);
		if(NULL == ether_aton_r(argv[2], (struct ether_addr *) bssid_dst))
			return csmd_cli_help(cli, rep, rep_len);
		csmd_cli_bss_trans(cli->csm_ctx, sta,
				bssid_dst);
	} else if (MATCH("erw", argv[0])) {
		uint8_t bssid[ETH_ALEN];
		if (argc < 3)
			return csmd_cli_erw_help(cli, rep, rep_len);
		if(NULL == ether_aton_r(argv[1], (struct ether_addr *)bssid))
			return csmd_cli_erw_help(cli, rep, rep_len);

		if (MATCH("add", argv[2]))
			return csmd_erw_add(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("del", argv[2]))
			return csmd_erw_del(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("clr_nr", argv[2]))
			return csmd_erw_clr_nr(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else
			return csmd_erw_update_from_file(cli, bssid, argc - 2, argv + 2, rep, rep_len);
	} else if (MATCH("mbo", argv[0])) {
		uint8_t bssid[ETH_ALEN];
		if (argc < 3)
			return csmd_cli_mbo_help(cli, rep, rep_len);
		if(NULL == ether_aton_r(argv[1], (struct ether_addr *)bssid))
			return csmd_cli_mbo_help(cli, rep, rep_len);

		if (MATCH("reg_frame", argv[2]))
			return csmd_mbo_reg_frame(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("update_ies", argv[2]))
			return csmd_mbo_update_ies(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("update_extcap", argv[2]))
			return csmd_mbo_update_extcap(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("update_3rd_cc", argv[2]))
			return csmd_mbo_update_3rd_cc(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("send_frame", argv[2]))
			return csmd_mbo_send_frame(cli, bssid, argc - 3, argv + 3, rep, rep_len);
		else
			return csmd_cli_mbo_help(cli, rep, rep_len);
	} else if (MATCH("seen", argv[0])) {
		uint8_t sta[ETH_ALEN];
		if (argc < 3)
			return csmd_cli_seen_help(cli, rep, rep_len);
		if (NULL == ether_aton_r(argv[1], (struct ether_addr *)sta))
			return csmd_cli_mbo_help(cli, rep, rep_len);
		if (MATCH("del", argv[2]))
			return csmd_seen_del(cli, sta, argc - 3, argv + 3, rep, rep_len);
		else if (MATCH("add", argv[2]))
			return csmd_seen_add(cli, sta, argc - 3, argv + 3, rep, rep_len);
		else
			return csmd_cli_seen_help(cli, rep, rep_len);
	} else if (MATCH("set_chan", argv[0])) {
		uint8_t radio[ETH_ALEN];
		if (argc < 4)
			return csmd_cli_set_chan_help(cli, rep, rep_len);
		if (NULL == ether_aton_r(argv[1], (struct ether_addr *)radio))
			return csmd_cli_set_chan_help(cli, rep, rep_len);

		return csmd_cli_set_chan(cli, radio, argc - 2, argv + 2, rep, rep_len);
	} else if (MATCH("set_intf_cfg", argv[0])) {
		uint8_t bssid[ETH_ALEN];
		if (argc < 4)
			return csmd_cli_set_intf_cfg_help(cli, rep, rep_len);
		if (NULL == ether_aton_r(argv[1], (struct ether_addr *)bssid))
			return csmd_cli_set_intf_cfg_help(cli, rep, rep_len);

		return csmd_cli_set_intf_cfg(cli, bssid, argc - 2, argv + 2, rep, rep_len);
	} else if (MATCH("roam", argv[0])) {
		uint8_t mac[ETH_ALEN];
		uint8_t target[ETH_ALEN];
		if (argc < 5)
			return csmd_cli_roam_help(cli, rep, rep_len);
		if (NULL == ether_aton_r(argv[1], (struct ether_addr *)mac))
			return csmd_cli_roam_help(cli, rep, rep_len);
		if (NULL == ether_aton_r(argv[2], (struct ether_addr *)target))
			return csmd_cli_roam_help(cli, rep, rep_len);

		return csmd_cli_roam(cli, mac, target, argc - 3, argv + 3, rep, rep_len);
	}

	return sprintf(rep, "successful\n");
}

static int csmd_cli_recv_ctrl_frame(struct csmd_cli *cli)
{
	int nread, rep_len;
	struct sockaddr_un addr;
	socklen_t addr_len;
	int argc;
	char *pos;
	char *argv[256] = { NULL };
	int i;

	memset(&rep, 0, sizeof(rep));
	memset(&req, 0, sizeof(req));
	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	nread = recvfrom(cli->ctrl_sock, req, sizeof(req), 0,
		(struct sockaddr *) &addr, &addr_len);
	req[sizeof(req) - 1] = '\0';
	if (nread < 0) {
		CSM_WARNING(PPREFIX
			"Failed to receive frame from ctrl socket: %s\n",
			strerror(errno));
		return -1;
	}

	argc = req[0];
	pos = &req[1];
	for (i = 0; i < argc && pos < (req + sizeof(req)); ++i, ++pos) {
		argv[i] = pos;
		while (*pos)
			++pos;
	}

	if (argc <= 1) {
		rep_len = csmd_cli_help(cli, VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)));
	} else {
		CSM_DEBUG(PPREFIX "recv cmd = %s", argv[1]);

		rep[0] = CTRL_MSG_END;
		if (MATCH("show", argv[1])) {
			int ret = csmd_cli_handle_show_req(cli, argc - 2, argv + 2, addr, addr_len);
			if(ret)
				rep_len = csmd_cli_help(cli, VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)));
			else
				return 0;
		} else if (MATCH("dbg", argv[1])
			|| MATCH("debug", argv[1])) {
			rep_len = csmd_cli_handle_dbg_req(cli, argc - 2, argv + 2,
				VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)));
		} else if (MATCH("cmd", argv[1])) {
			rep_len = csmd_cli_handle_cmd_req(cli, argc - 2, argv + 2,
				VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)));
		} else if (MATCH("version", argv[1])) {
#ifdef CSM_SUBVERSION
			rep_len = snprintf(VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)),
				"version: %s; subversion: %s\n", CSM_VERSION, CSM_SUBVERSION);
#else
			rep_len = snprintf(VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)),
				"version: %s; subversion: unknown\n", CSM_VERSION);
#endif
		} else {
			rep_len = csmd_cli_help(cli, VALID_CTRL_MSG_HEAD(rep), VALID_CTRL_MSG_LEN(sizeof(rep)));
		}
	}

	if (sendto(cli->ctrl_sock, rep, rep_len + RESERVE_LEN, 0,
		(struct sockaddr *) &addr, addr_len) < 0) {
		CSM_WARNING(PPREFIX
			"Failed to send frame to ctrl socket: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

#define FD_SET_ADV(fd, set) \
	do {\
		FD_SET(fd, set);\
		if (fd >= max_fd)\
			max_fd = fd + 1;\
	} while (0)

static int csmd_cli_process_ctrl(struct csmd_cli *cli)
{
	int max_fd = 0;
	struct timeval timeout;
	fd_set readset;
	FD_ZERO(&readset);
	FD_SET_ADV(cli->ctrl_sock, &readset);

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	if (select(max_fd, &readset, 0, 0, &timeout) < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;
	}

	if (FD_ISSET(cli->ctrl_sock, &readset))
		csmd_cli_recv_ctrl_frame(cli);
	return 0;

}


static void *csmd_cli_background_thread(void *ctx)
{
	struct csmd_cli *cli = (struct csmd_cli *) ctx;


	while (cli->running) {
		csmd_cli_process_ctrl(cli);
	}
	return NULL;
}

static void csmd_cli_unload(void *ctx)
{
	struct csmd_cli *cli = (struct csmd_cli *) ctx;
	if (cli) {
		if (cli->running) {
			cli->running = 0;
			pthread_join(cli->thread, NULL);
		}
		free(ctx);
	}
}

static void *csmd_cli_load(void *csm_ctx)
{
	struct csmd_cli *cli = calloc(1, sizeof(struct csmd_cli));
	if (cli) {
		cli->csm_ctx = csm_ctx;
		cli->ctrl_sock = csmd_cli_ctrl_sock_open();
		if (cli->ctrl_sock < 0) {
			goto fail;
		}
		cli->running = 1;
		pthread_create(&cli->thread, NULL,
			       csmd_cli_background_thread, cli);

	}
	return cli;

fail:
	if (cli)
		free(cli);
	return NULL;
}

static struct csm_misc_plugin csmd_cli_misc_plugin = {
	.plugin_head =
	    INIT_PLUGIN_HEAD(NAME, csmd_cli_load, csmd_cli_unload, NULL,
			     NULL),
};

static struct csmd_cli_desc g_csmd_cli_desc = {
	.desc = INIT_PLUGIN_FILE_DESC(CSM_MISC_MAGIC, CSM_MISC_VERSION, 1),
	.plugin[0] = &csmd_cli_misc_plugin,
};

struct csm_plugin_file_desc *csm_plugin_get_desc(void)
{
	return (struct csm_plugin_file_desc *) &g_csmd_cli_desc;
}
