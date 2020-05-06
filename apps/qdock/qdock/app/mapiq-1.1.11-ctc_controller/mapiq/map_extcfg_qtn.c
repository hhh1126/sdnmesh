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

#include "map_common.h"
#include "map_extcfg.h"

#include "map_extcfg_qtn.h"


#define CALL_QCSAPI_SET_WIFI_PARAM( _IFNAME, _PARAM, _VALUE)\
  do { \
	int cur; \
	int ret = qcsapi_wifi_get_parameter(_IFNAME, _PARAM, &cur); \
	if (ret < 0) { \
	  EXTCFG_ERROR("%s:%d-qcsapi_wifi_get_parameter %s for ifname(%s) failed, errno(%d)\n", __func__, __LINE__, #_PARAM, _IFNAME, ret); \
      cur = !_VALUE; \
	} \
	if (cur != _VALUE) { \
	  EXTCFG_DEBUG("%s:%d-qcsapi_wifi_set_parameter %s %d for %s\n",__func__, __LINE__, #_PARAM, _VALUE, _IFNAME); \
	  qcsapi_wifi_set_parameter(_IFNAME, _PARAM, _VALUE); \
	} \
  } while (0)

static struct blob_buf b;
static struct ubus_context *g_ubus_ctx = NULL;

static const struct blobmsg_policy extcfg_wiphy_policy[NUM_MAP_EXTCFG_ATTRS] = {
	[MAP_EXTCFG_WIPHY_ATTR_WIPHY] = { .name = MAP_EXTCFG_WIPHY_ATTR_WIPHY_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_WIPHY_ATTR_TEARDOWN] = { .name = MAP_EXTCFG_WIPHY_ATTR_TEARDOWN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy extcfg_policy[NUM_MAP_EXTCFG_ATTRS] = {
	[MAP_EXTCFG_ATTR_WDEV] = { .name = MAP_EXTCFG_ATTR_WDEV_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_ATTR_WIPHY] = { .name = MAP_EXTCFG_ATTR_WIPHY_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAP_EXTCFG_ATTR_MODE] = { .name = MAP_EXTCFG_ATTR_MODE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_SSID] = { .name = MAP_EXTCFG_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_EXTCFG_ATTR_AUTH] = { .name = MAP_EXTCFG_ATTR_AUTH_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_ENCRYP] = { .name = MAP_EXTCFG_ATTR_ENCRYP_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_KEY] = { .name = MAP_EXTCFG_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_EXTCFG_ATTR_DISABLE] = { .name = MAP_EXTCFG_ATTR_DISABLE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_WPS] = { .name = MAP_EXTCFG_ATTR_WPS_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_MAP_TYPES] = { .name = MAP_EXTCFG_ATTR_MAP_TYPES_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_BACKHAUL] = { .name = MAP_EXTCFG_ATTR_BACKHAUL_NAME, .type = BLOBMSG_TYPE_TABLE },
	[MAP_EXTCFG_ATTR_4ADDR] = { .name = MAP_EXTCFG_ATTR_4ADDR_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_ATTR_HIDE_SSID] = { .name = MAP_EXTCFG_ATTR_HIDE_SSID_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy extcfg_backhaul_policy[NUM_MAP_EXTCFG_BACKHAUL_ATTRS] = {
	[MAP_EXTCFG_BACKHAUL_ATTR_SSID] = { .name = MAP_EXTCFG_BACKHAUL_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC },
	[MAP_EXTCFG_BACKHAUL_ATTR_AUTH] = { .name = MAP_EXTCFG_BACKHAUL_ATTR_AUTH_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_BACKHAUL_ATTR_ENCRYP] = { .name = MAP_EXTCFG_BACKHAUL_ATTR_ENCRYP_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAP_EXTCFG_BACKHAUL_ATTR_KEY] = { .name = MAP_EXTCFG_BACKHAUL_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

#define PARAM_TYPE_STRING 	0
#define PARAM_TYPE_INT		1
#define CFGMETHOD_TYPE_IOCTL	0
#define CFGMETHOD_TYPE_QWECFG	1

#ifdef Q_OPENWRT
#define QWECFG_OUTPUT_MAX	1024
#endif


#ifdef SPARTAN_PLATFORM

#include "uci.h"
#include "map_api.h"

#define MAP_MAX_BSSID_AP    (8)
#define MAP_MAX_BSSID_24G   (8)
#define MAP_MAX_BSSID_RTL_24G   (5)


#define MAP_UCI_BUF_LEN     (128)
#define MAP_UCI_VIF_LEN     (8)

#define UCI_PKG_WIRELESS    "wireless"

#define UCI_SEC_QTN         "qtn"

#define UCI_OPT_MAP_BBSS    "map_bbss"
#define BBSS_IF_IDX         (7)
#define BBSS_IF_IDX_CHAR    '7'
#define UCI_BBSS_IF_R0      "r0vap7"
#define UCI_BBSS_IF_R1      "r1vap7"

/*
 * UCI virtual interface (wifix, wlanx) to from driver ifname
 * 				(wifix, wlan1, vapn.wlan1, wifix_x)
 * Input:
 *  ifname:     interface name in drvier, e.g. wifix, wlan1, vapx.wlan1, wifix_x
 *  vif   :     buf to contain UCI virtual interface, e.g. sta, r(x)vap(x)
 *      BBIC4:
 *              AP: wifi0 ~ wifi7 --> r0vap0 ~ r0vap7
 *                  wlan1, vap(x)wlan1  --> r1vap0, r1vap(x+1)
 *              RP: wifi0, wifi1 ~ wifi7 --> sta, r0vap0 ~ r0vap7
 *                  wlan1, vap(x)wlan1  --> r1vap0, r1vap(x+1)
 *      BBIC5:
 *              AP: wifi0_0 ~ wifi0_7 --> r0vap0 ~ r0vap7
 *                  wifi2_0 ~ wifi2_7 --> r1vap0 ~ r1vap7
 *              RP: wifi0_0, wifi0_1 ~ wifi0_7 --> sta, r0vap0 ~ r0vap7
 *                  wifi2_0 ~ wifi2_7 --> r1vap0 ~ r1vap7
 *  buf_len:    sizeof(vif)
 * Output:
 *  0  :        success
 *  < 0:        fail
 */
int ifname_to_virtual(const char *ifname, char *vif, const int buf_len)
{
	int ret = 0, vap_idx = -1, radio_idx = -1;
	int is_repeater = 0;

	if (ifname == NULL || vif == NULL) {
		EXTCFG_ERROR("input NULL pointer\n");
		return -2;
	}
	vif[0] = '\0';

	ret = sscanf(ifname, "wifi%d_%d", &radio_idx, &vap_idx);
	/* BBIC4 5G Interface*/
	if (1 == ret) {
		vap_idx = radio_idx;
		radio_idx = 0;
	}
	/* BBIC5 2G Interface*/
	else if (2 == ret && 2 == radio_idx) {
		radio_idx = 1;
	}
	ret = 0;

	is_repeater = qcsapi_wifi_verify_repeater_mode();
	if (vap_idx >= 0 && vap_idx < MAP_MAX_BSSID_AP) {
		/* currently only 5G backhhaul is supported */
		if (is_repeater && radio_idx == 0) {
			if (vap_idx == 0) {
				strncpy(vif, "sta", buf_len);
				vif[buf_len - 1] = '\0';
				goto RETURN;
			/* r0vap7 is fixed as backhaul */
			} else if (vap_idx != BBSS_IF_IDX)
				vap_idx--;
		}

		snprintf(vif, buf_len, "r%dvap%d", radio_idx, vap_idx);
		goto RETURN;
	}

	if (strncmp(ifname, "wlan1", sizeof("wlan1")) == 0) {
		strncpy(vif, "r1vap0", buf_len);
		goto RETURN;
	}

	vap_idx = -1;
	sscanf(ifname, "vap%d.wlan1", &vap_idx);
	if (vap_idx < 0 || vap_idx > (MAP_MAX_BSSID_RTL_24G - 1)) {
		ret = -4;
		goto RETURN;
	}
	snprintf(vif, buf_len, "r1vap%d", vap_idx + 1);
	vif[buf_len - 1] = '\0';
	ret = 0;

RETURN:
	// EXTCFG_DEBUG("%s mode, ret=%d, ifname=%s, vif=%s\n",
	//		is_repeater? "RP":"AP", ret, ifname,
	//		(strlen(vif) < buf_len) ? vif : "NULL");
	return ret;
}

/*
 * UCI virtual interface (wifix, wlanx) to driver ifname (wifix, wlan1, vapn.wlan1, wifix_x)
 * Please refer to "ifname_to_virtual" function for the detailed interface mapping.
 * Input:
 *  ifname:     buf to interface name in drvier, e.g. wifix, wlan1, vapx.wlan1, wifix_x
 *  vif   :     UCI virtual interface, e.g. sta, r(x)vap(x)
 *  buf_len:    sizeof(ifname)
 * Output:
 *  0  :        success
 *  < 0:        fail
 */
int virtual_to_ifname(char *ifname, const char *vif, const int buf_len)
{
	int ret = 0, vap_idx = -1, radio_idx = -1;
	int is_repeater = 0, bbic5 = 0;
	char ifstatus[32] = {0};

	if (ifname == NULL || vif == NULL) {
		EXTCFG_ERROR("input NULL pointer\n");
		return -1;
	}

	ret = qcsapi_interface_get_status("wifi0_0", ifstatus);
	if (ret == 0)
		bbic5 = 1;

	ifname[0] = '\0';

	is_repeater = qcsapi_wifi_verify_repeater_mode();
	ret = 0;

	/* currently only 5G backhhaul is supported */
	if (strncmp(vif, "sta", sizeof("sta")) == 0) {
		if (!is_repeater) {
			EXTCFG_ERROR("virtual interface 'sta' will not work in AP mode\n");
			ret = -2;
			goto RETURN;
		}

		if (bbic5)
			strncpy(ifname, "wifi0_0", buf_len);
		else
			strncpy(ifname, "wifi0", buf_len);

		ifname[buf_len - 1] = '\0';
		ret = 0;
		goto RETURN;
	}

	sscanf(vif, "r%dvap%d", &radio_idx, &vap_idx);
	if (radio_idx < 0 || radio_idx > 1 ||
		vap_idx < 0 || vap_idx >= MAP_MAX_BSSID_AP) {
		ret = -3;
		goto RETURN;
	}

	if (bbic5) {
		if (radio_idx == 1)
			radio_idx = 2;

		if (is_repeater && radio_idx == 0 && vap_idx != BBSS_IF_IDX)
			vap_idx += 1;

		snprintf(ifname, buf_len, "wifi%d_%d", radio_idx, vap_idx);
	} else {
		if (radio_idx == 1) {
			if (vap_idx == 0)
				snprintf(ifname, buf_len, "wlan1");
			else
				snprintf(ifname, buf_len, "vap%d.wlan1", vap_idx - 1);
		} else {
			if (is_repeater && radio_idx == 0 && vap_idx != BBSS_IF_IDX)
				vap_idx += 1;

			snprintf(ifname, buf_len, "wifi%d", vap_idx);
		}
	}

	ret = 0;
	ifname[buf_len - 1] = '\0';

RETURN:
	// EXTCFG_DEBUG("%s mode, ret=%d, vif=%s ---> ifname=%s\n", is_repeater? "RP:":"AP:",
	// 			ret, (strlen(vif) < buf_len) ? vif : "NULL", ifname);
	return ret;
}

/*
 * Get option value
 * Input:
 *	opt:	opt string in config.section.option
 *	value:	buf to contain the opton value
 *	vlen:	strlen(value)
 * Output:
 *	0:	success
 *	< 0:				fail
 */
int uci_get_option(const char *opt, char *value, int vlen)
{
	int ret = 0;
	struct uci_context *ctx = NULL;
	struct uci_ptr ptr_config;
	char uci_option[MAP_UCI_BUF_LEN] = {0}, *opt_v_str = NULL;

	if (opt == NULL || value == NULL) {
		EXTCFG_ERROR("%s() NULL input\n", __func__);
		return -1;
	}

	ctx = uci_alloc_context();
	if (!ctx) {
		EXTCFG_ERROR("uci_alloc_context error\n");
		return -2;
	}

	snprintf(uci_option, sizeof(uci_option) - 1, "%s", opt);
	if (uci_lookup_ptr(ctx, &ptr_config, uci_option, true)!= UCI_OK || !ptr_config.s) {
		EXTCFG_ERROR("uci: Entry not found: %s\n", opt);
		ret = -3;
		goto RETURN;
	}

	opt_v_str = ptr_config.o->v.string;
	if (!opt_v_str || strlen(opt_v_str) > vlen) {
		EXTCFG_ERROR("uci option value is invalid\n");
		ret = -4;
		goto RETURN;
	}
	strcpy(value, opt_v_str);

RETURN:
	if (ctx) {
		uci_free_context(ctx);
		ctx = NULL;
	}
	// EXTCFG_DEBUG("%s() opt=%s vlen=%d value='%s'\n", __func__, opt, vlen, value?value:"NULL");

	return ret;
}

/*
 * Set and/or commit option
 * Input:
 *	opt:		opt string in config.section.option
 *	value:		string value
 * Output:
 *	0:	success
 *	< 0:				fail
 */
int uci_set_option(const char *opt, const char *value)
{
	int ret = 0;
	struct uci_context *ctx = NULL;
	struct uci_ptr ptr_config;
	char uci_option[MAP_UCI_BUF_LEN] = {0};

	if (opt == NULL || value == NULL) {
		EXTCFG_ERROR("%s() NULL input\n", __func__);
		return -1;
	}

	ctx = uci_alloc_context();
	if (!ctx) {
		EXTCFG_ERROR("uci_alloc_context error\n");
		return -2;
	}

	snprintf(uci_option, sizeof(uci_option)-1, "%s", opt);
	if (uci_lookup_ptr(ctx, &ptr_config, uci_option, true)!= UCI_OK || !ptr_config.s) {
		EXTCFG_ERROR("uci: Entry not found: %s\n", opt);
		ret = -3;
		goto RETURN;
	}

	ptr_config.value = value;
	if (uci_set(ctx, &ptr_config) != UCI_OK) {
		EXTCFG_ERROR("%s() failed in uci_set\n", __func__);
		ret = -4;
		goto RETURN;
	}

	if (uci_commit(ctx, &ptr_config.p, false) != UCI_OK) {
		EXTCFG_ERROR("failed to commit changes\n");
		ret = -5;
		goto RETURN;
	}

RETURN:
	if (ctx) {
		uci_free_context(ctx);
		ctx = NULL;
	}
	// EXTCFG_DEBUG("%s() opt=%s value='%s'\n", __func__, opt, value);

	return ret;
}

/*
 * Set and/or commit option of string data type
 * Input:
 *	config:	config file of UCI
 *	section:	section in config file
 *	option:	option in section
 *	value:	value of option
 * Output:
 *	0:	success
 *	< 0:	fail
 */
int uci_set_option_str(const char *config, const char *section, const char *option, const char *value)
{
	int ret = 0;
	char opt[MAP_UCI_BUF_LEN];

	if (!config || !section || !option || !value ) {
		EXTCFG_ERROR("%s() NULL input\n", __func__);
		return -1;
	}

	ret = snprintf(opt, MAP_UCI_BUF_LEN, "%s.%s.%s", config, section, option);
	if (ret < 0 || ret >= MAP_UCI_BUF_LEN) {
		return -2;
	}
	ret = uci_set_option(opt, value);

	return ret;
}

/*
 * Set and/or commit option of integer data type
 * Input:
 *	config:	config file of UCI
 *	section:	section in config file
 *	option:	option in section
 *	value:	value of option
 * Output:
 *	0:	success
 *	< 0:		fail
 */
int uci_set_option_int(const char *config, const char *section, const char *option, const int value)
{
	int ret = 0;
	char opt[MAP_UCI_BUF_LEN], str_value[MAP_UCI_BUF_LEN];

	if (!config || !section || !option) {
		EXTCFG_ERROR("%s() NULL input\n", __func__);
		return -1;
	}

	ret = snprintf(opt, MAP_UCI_BUF_LEN, "%s.%s.%s", config, section, option);
	if (ret < 0 || ret >= MAP_UCI_BUF_LEN) {
		return -2;
	}
	ret = snprintf(str_value, MAP_UCI_BUF_LEN, "%d", value);
	if (ret < 0 || ret >= MAP_UCI_BUF_LEN) {
		return -3;
	}

	ret = uci_set_option(opt, str_value);

	return ret;
}

/*
 * Get  radio name
 * Input:
 *	ifname:	real interface name
 *	radio_name:	after call, radio name is filled
 *	vlen:	max value len of radio name
 * Output:
 *	0:	success
 *	< 0:		fail
 */
int uci_wifi_get_device_by_ifname(const char *ifname, char *radio_name, int vlen)
{
	int ret = 0;
	char opt[MAP_UCI_BUF_LEN], buf[MAP_UCI_BUF_LEN];

	if (!ifname || !radio_name) {
		EXTCFG_ERROR("%s() NULL input\n", __func__);
		return -1;
	}

	ret = ifname_to_virtual(ifname, buf, sizeof(buf));
	if (ret != 0)
		return ret;

	snprintf(opt, MAP_UCI_BUF_LEN, "%s.%s.device", UCI_PKG_WIRELESS, buf);
	ret = uci_get_option(opt, radio_name, vlen);

	return ret;
}

#define UCI_SET_OPTION_STR(config, section, option, value, ret) \
do { \
	if (ret == 0) \
		ret = uci_set_option_str(config, section, option, value); \
} while (0)

#define UCI_SET_OPTION_INT(config, section, option, value, ret) \
do { \
	if (ret == 0) \
		ret = uci_set_option_int(config, section, option, value); \
} while (0)

#define UCI_SET_RADIO_OPTION_STR(ifname, option, value, ret) \
do { \
	char radio_name[32]; \
	ret = uci_wifi_get_device_by_ifname(ifname, radio_name, sizeof(radio_name)); \
	if (ret == 0) \
		ret = uci_set_option_str(UCI_PKG_WIRELESS, radio_name, option, value); \
} while (0)

#define UCI_SET_RADIO_OPTION_INT(ifname, option, value, ret) \
do { \
	char radio_name[IFNAME_MAXLEN + 1]; \
	ret = uci_wifi_get_device_by_ifname(ifname, radio_name, sizeof(radio_name)); \
	if (ret == 0) \
		ret = uci_set_option_int(UCI_PKG_WIRELESS, radio_name, option, value); \
} while (0)

#define UCI_SET_WIRELESS_IF_STR(ifname, option, value) \
do { \
	int ret_uci; \
	char vif[IFNAME_MAXLEN + 1] = {0};\
	ret_uci = ifname_to_virtual(ifname, vif, sizeof(vif)); \
	if (ret_uci == 0) \
		uci_set_option_str(UCI_PKG_WIRELESS, vif, option, value); \
} while (0)

#define UCI_SET_WIRELESS_IF_INT(ifname, option, value) \
do { \
	int ret_uci; \
	char vif[IFNAME_MAXLEN + 1] = {0};\
	ret_uci = ifname_to_virtual(ifname, vif, sizeof(vif)); \
	if (ret_uci == 0) \
		uci_set_option_int(UCI_PKG_WIRELESS, vif, option, value); \
} while (0)

/*
 * Set wirless.[section].encryption
 * Input:
 *	ifname:		interface name in drvier, e.g. wifix, wlan1, vapn.wlan1
 *	vif:		interface name for UCI, e.g r0vap1
 *	auth:		authentication mode defined in MAP, see map_extcfg.h
 *	encryp:		encryption mode defined in MAP, see map_extcfg.h
 * Output:
 *	0:	success
 *	< 0:	fail
 */
int uci_set_wifi_security(const char *ifname, char* vif, uint32_t auth, uint32_t encryp)
{
	int ret = 0;
	char vvif[IFNAME_MAXLEN + 1], new_encryp[MAP_UCI_BUF_LEN] = {0};

	if (!ifname && !vif)
		return -1;

	if (!auth && !encryp)
		return -2;

	if ((auth == MAP_IEEE80211_AUTH_MODE_WPA2PSK) &&
		(encryp == MAP_IEEE80211_ENCRYP_MODE_AES))
		strcpy(new_encryp, "psk2+aes");
	else if ((auth == MAP_IEEE80211_AUTH_MODE_WPAPSK) &&
			(encryp == MAP_IEEE80211_ENCRYP_MODE_AES))
		strcpy(new_encryp, "psk+aes");
	else if ((auth == MAP_IEEE80211_AUTH_MODE_WPA2) &&
			(encryp == MAP_IEEE80211_ENCRYP_MODE_AES))
		strcpy(new_encryp, "wpa2");
	else if ((auth == MAP_IEEE80211_AUTH_MODE_WPA) &&
			(encryp == MAP_IEEE80211_ENCRYP_MODE_AES))
		strcpy(new_encryp, "wpa");
	else if (auth == MAP_IEEE80211_AUTH_MODE_OPEN)
		strcpy(new_encryp, "none");
	else {
		EXTCFG_ERROR("unkown auth: 0x04%x and encryption:0x04%x combination for UCI\n",
					auth, encryp);
		return -3;
	}

	if (ifname && !vif) {
		ret = ifname_to_virtual(ifname, vvif, sizeof(vvif));
		if (ret != 0)
			return -3;
		vif = vvif;
	}

	UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, vif, "encryption", new_encryp, ret);

	// EXTCFG_DEBUG("auth: 0x04%x and encryption:0x04%x, new new_encryp str is: %s\n",
	//			auth, encryp, new_encryp);

	return ret;
}

#define UCI_SET_WIFI_SECURITY(ifname, vif, auth, encryp) \
do { \
	uci_set_wifi_security(ifname, vif, auth, encryp); \
} while (0)

#else //SPARTAN_PLATFORM

#define UCI_SET_OPTION_STR(config, section, option, value, ret)
#define UCI_SET_OPTION_INT(config, section, option, value, ret)
#define UCI_SET_RADIO_OPTION_STR(ifname, option, value, ret)
#define UCI_SET_RADIO_OPTION_INT(ifname, option, value, ret)
#define UCI_SET_WIRELESS_IF_STR(ifname, option, value)
#define UCI_SET_WIRELESS_IF_INT(ifname, option, value, ret)
#define UCI_SET_WIFI_SECURITY(ifname, vif, auth, encryp)

#endif //SPARTAN_PLATFORM


static int rtl_qwecfg_get(char *p_param, int len_param,
		char *value, int *p_len_value, int param_type, int method_type)
{
#ifdef Q_OPENWRT
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
	int ret = 0;
#else
	char qwecfg_cmd[64] = {0}, tmp[128] = {0};
	char *real_value = NULL;
	int len_read;
	FILE *fp = NULL;
#endif

	if (NULL == p_param) {
		EXTCFG_ERROR("rtl_qwecfg_get:: incomming param is NULL\n");
		return -1;
	}

	if (value == NULL) {
		EXTCFG_ERROR("rtl_qwecfg_get:: return value buffer is NULL\n");
		return -2;
	}

#ifdef Q_OPENWRT
	EXTCFG_DEBUG("rtl_qwecfg_get:: %s\n", p_param);
	if (ret = qcsapi_qwe_command("qweconfig", "get", (const char *)p_param, NULL, qwecfg_output, QWECFG_OUTPUT_MAX))
	{
		EXTCFG_ERROR("Error: rtl_qwecfg_get:: qcsapi_qwe_command return error %d\n", ret);
		return ret;
	}

	// TBD: need check if str length of qwecfg_output > value buffer size
	strcpy(value, qwecfg_output);
	*p_len_value = strlen(qwecfg_output);
	EXTCFG_DEBUG("rtl_qwecfg_get: value=%s, len_value=%d\n", value, *p_len_value);
#else
	if (method_type == CFGMETHOD_TYPE_IOCTL)
		strcpy(qwecfg_cmd, "iwpriv wlan0 get_mib ");
	else
		strcpy(qwecfg_cmd, "qweconfig get ");

	if ((strlen(qwecfg_cmd) + strlen(p_param)) < 64)
		strcat(qwecfg_cmd, p_param);
	else
		EXTCFG_ERROR("rtl_qwecfg_get:: len of param is overrunning\n");
	fp = popen(qwecfg_cmd, "r");
	if (!fp)
		return -1;
	len_read = 128; // The Max read len = KEY_MAXLEN + sizeof(prefix) + 1, here assume 128 is enough
	if (fgets(tmp, len_read, fp)) {
		if (method_type == CFGMETHOD_TYPE_IOCTL) {
			real_value = strstr(tmp, "get_mib:");
			*p_len_value = strlen(real_value+strlen("get_mib:"));
			memcpy((char *)value, real_value + strlen("get_mib:"), *p_len_value);
		}
		else {
			*p_len_value = strlen(tmp);
			memcpy(value, (char *)tmp, *p_len_value);
		}
	}
	pclose(fp);
	EXTCFG_DEBUG("rtl_qwecfg_get: dump******[%s]******, value=%s, len_value=%d\n", qwecfg_cmd, value, *p_len_value);
#endif

	return 0;
}

static int rtl_qwecfg_set(char *p_param, void *value, int len_value, int param_type, int method_type)
{
#ifdef Q_OPENWRT
	char qwecfg_value[8] = {0};
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
	int ret;
#else
	char qwecfg_cmd[256] = {0}, method[32] = {0};
#endif

	if (NULL == p_param) {
		EXTCFG_ERROR("rtl_qwecfg_set:: incomming param is NULL\n");
		return -1;
	}

#ifdef Q_OPENWRT
	if (param_type == PARAM_TYPE_INT) /*using len_value for the int value*/
		sprintf(qwecfg_value, "%d", len_value);
	else
		sprintf(qwecfg_value, "%s", (char *)value);

	EXTCFG_DEBUG("rtl_qwecfg_set: %s, %s\n", p_param, qwecfg_value);
	if (ret = qcsapi_qwe_command("qweconfig", "set", (const char *)p_param, (const char *)qwecfg_value, qwecfg_output, QWECFG_OUTPUT_MAX))
	{
		EXTCFG_ERROR("Error: rtl_qwecfg_set:: qcsapi_qwe_command return error %d\n", ret);
		return ret;
	}
#else
	if (method_type == CFGMETHOD_TYPE_IOCTL)
		strcpy(method, "iwpriv wlan0 set_mib");
	else
		strcpy(method, "qweconfig set");

	if (param_type == PARAM_TYPE_INT) /*using len_value for the int value*/
		sprintf(qwecfg_cmd, "%s %s %d", method, p_param, len_value);
	else
		sprintf(qwecfg_cmd, "%s %s \"%s\"", method, p_param, (char *)value);
	EXTCFG_DEBUG("rtl_qwecfg_set: dump******[%s]******\n", qwecfg_cmd);
	system(qwecfg_cmd);
#endif

	return 1;
}

static const char * rtl_config_ifnames[] = {
	"wlan1",
	"vap0.wlan1",
	"vap1.wlan1",
	"vap2.wlan1",
	"vap3.wlan1",
};

static void rtl_enable_wdev(int index, int enable)
{
	char param[32];

	sprintf(param, "enable.%s", rtl_config_ifnames[index]);
	rtl_qwecfg_set(param, NULL, enable, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG);
#ifdef RTL_USE_CONFIGURED
	sprintf(param, "configured.%s", rtl_config_ifnames[index]);
	rtl_qwecfg_set(param, NULL, enable, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG);
#endif
}

static int rtl_extcfg_find_available_index(void)
{
	int index, len_value = 0, enable;
	char param[32] = {0};
	char value[8] = {0};

	for (index = 0; index <= 4; index++) {
#ifdef RTL_USE_CONFIGURED
		sprintf(param, "configured.%s", rtl_config_ifnames[index]);
		rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG);
#else
		sprintf(param, "enable.%s", rtl_config_ifnames[index]);
		rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG);
#endif
		enable = atoi(value);
		if (0 == enable)
			return index;
	}
	return -1;
}

static int rtl_extcfg_disable_radio(void)
{
#ifdef Q_OPENWRT
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
#endif
	EXTCFG_DEBUG("rtl_extcfg_disable_radio, tear down\n");

#ifdef Q_OPENWRT
	qcsapi_qwe_command("qweconfig", "default", NULL, NULL, qwecfg_output, QWECFG_OUTPUT_MAX);
#else
	system("qweconfig default");
#endif
	rtl_enable_wdev(0, 0);
#ifdef Q_OPENWRT
	qcsapi_qwe_command("qweaction", "wlan1", "commit", NULL, qwecfg_output, QWECFG_OUTPUT_MAX);
#else
	system("qweaction wlan1 commit");
#endif

	return 0;
}

static int rtl_config_bss_wdev(struct blob_attr **info, int index)
{
	int ret = 0;
	uint8_t *tmp_data;
	uint32_t tmp_data_len, auth = MAP_IEEE80211_AUTH_MODE_OPEN, cipher = MAP_IEEE80211_ENCRYP_MODE_NONE, wps;
	char ssid[SSID_MAXLEN + 1] = { 0 }, param[32] = {0}, value[34] = {0};

	if ((index < 0) || (index > 4)){
		EXTCFG_ERROR("index %d for rtl is not valid!\n", index);
		return -1;
	}

	if (info[MAP_EXTCFG_ATTR_SSID]) {
		tmp_data = blobmsg_data(info[MAP_EXTCFG_ATTR_SSID]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_ATTR_SSID]);
		if (tmp_data_len > SSID_MAXLEN) {
			EXTCFG_ERROR("ssid %s of len[%d] exceeds the max allowable length[%d]\n",
				tmp_data, tmp_data_len, SSID_MAXLEN);
			return -1;
		}
		memcpy(ssid, tmp_data, tmp_data_len);
		sprintf(param, "ssid.%s", rtl_config_ifnames[index]);
		UCI_SET_WIRELESS_IF_STR(rtl_config_ifnames[index], "ssid", ssid);
		ret = rtl_qwecfg_set(param, ssid, tmp_data_len, PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG);
	}

	if (info[MAP_EXTCFG_ATTR_AUTH]) {
		memset(param, 0, 32);
		sprintf(param, "encryption.%s", rtl_config_ifnames[index]);
		auth = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_AUTH]);
		switch(auth) {
			case MAP_IEEE80211_AUTH_MODE_OPEN:
			case MAP_IEEE80211_AUTH_MODE_SHARED:
				ret = rtl_qwecfg_set(param, "open", strlen("open"), PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG);
			break;
			case MAP_IEEE80211_AUTH_MODE_WPA:
			case MAP_IEEE80211_AUTH_MODE_WPA2:
				EXTCFG_ERROR("unsupport 802_1X\n");
			break;
			case MAP_IEEE80211_AUTH_MODE_WPAPSK:
				memset(value, 0, 32);
				sprintf(value, "%s", "wpa_");
			break;
			case MAP_IEEE80211_AUTH_MODE_WPA2PSK:
				memset(value, 0, 32);
				sprintf(value, "%s", "wpa2_");
			break;
			default:
				EXTCFG_ERROR("unknown auth type :0x04%x\n", auth);
			break;
		}
	}

	if (info[MAP_EXTCFG_ATTR_ENCRYP]) {
		cipher = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_ENCRYP]);
		if(cipher == MAP_IEEE80211_ENCRYP_MODE_NONE &&
			auth != MAP_IEEE80211_AUTH_MODE_OPEN)
			EXTCFG_ERROR("cipher mode none is only allowed at open auth mode\n");

		switch(cipher) {
			case MAP_IEEE80211_ENCRYP_MODE_TKIP:
				strcat(value, "tkip");
				ret = rtl_qwecfg_set(param, value, strlen(value), PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG);
			break;
			case MAP_IEEE80211_ENCRYP_MODE_AES:
				strcat(value, "aes");
				ret = rtl_qwecfg_set(param, value, strlen(value), PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG);
			break;
			case MAP_IEEE80211_ENCRYP_MODE_WEP:
				EXTCFG_ERROR("unsupport ENCRY type WEP\n");
			break;
			default:
				EXTCFG_ERROR("unknown ENCRY type :0x04%x\n", cipher);
			break;
		}
	}

	UCI_SET_WIFI_SECURITY(rtl_config_ifnames[index], NULL, auth, cipher);

	if (info[MAP_EXTCFG_ATTR_KEY]) {
		char key[KEY_MAXLEN + 1];
		tmp_data = blobmsg_data(info[MAP_EXTCFG_ATTR_KEY]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_ATTR_KEY]);
		if (tmp_data_len > KEY_MAXLEN) {
			EXTCFG_ERROR("key len[%d] exceeds the max allowable length[%d]\n",
				tmp_data_len, KEY_MAXLEN);
			return -1;
		}
		memcpy(key, tmp_data, tmp_data_len);
		key[tmp_data_len] = '\0';
		memset(param, 0, 32);
		sprintf(param, "passphrase.%s", rtl_config_ifnames[index]);
		UCI_SET_WIRELESS_IF_STR(rtl_config_ifnames[index], "key", key);
		ret = rtl_qwecfg_set(param, key, tmp_data_len, PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG);
	}

	if (info[MAP_EXTCFG_ATTR_WPS]) {
		wps = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_WPS]);
		if (wps)
			system("/root/wscd -sig_start wlan0");
	}

	if (info[MAP_EXTCFG_ATTR_4ADDR])
		EXTCFG_ERROR("interface %s do not support set 4 address mode\n", rtl_config_ifnames[index]);

	return ret;
}


static int rtl_extcfg_create_wdev(int mode)
{
	int index;

	index = rtl_extcfg_find_available_index();
	if (index >= 0) {
		rtl_enable_wdev(index, 1);
	}
	return index;
}

#define INTERFACE_DEL 0
#define INTERFACE_ADD 1
#ifdef SPARTAN_PLATFORM
int uci_wifi_mod_intf(const char *ifname, int act)
{
	char vif[IFNAME_MAXLEN + 1] = {0}, cmd[MAP_UCI_BUF_LEN] = {0};
	int ret = -1;
	ret = ifname_to_virtual(ifname, vif, sizeof(vif));
	if(ret == 0){
		snprintf(cmd, MAP_UCI_BUF_LEN, "uci_wifi %s %s 1",
			act == INTERFACE_DEL ? "uci_del_iface" : "uci_add_iface", vif);
		system(cmd);
	}
	return ret;
}
static int rtl_extcfg_mod_intf(int index,  int act)
{
	int ret = -1;
	ret = uci_wifi_mod_intf(rtl_config_ifnames[index], act);
	return ret;
}
#else
#define uci_wifi_mod_intf(x , y)
#define rtl_extcfg_mod_intf(x, y)
#endif

static int rtl_extcfg_add_wdev(struct blob_attr** cfg)
{
	int ret;
	int index;
	int mode = blobmsg_get_u32(cfg[MAP_EXTCFG_ATTR_MODE]);
#ifdef Q_OPENWRT
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
#endif

	if (mode != MAP_INTERFACE_TYPE_AP) {
		EXTCFG_ERROR("non-AP mode is not support on Rtl!\n");
		return -1;
	}
	if ((index = rtl_extcfg_create_wdev(mode)) < 0){
		EXTCFG_ERROR("no avaliable interface on Rtl!\n");
		return -2;
	}else{
		rtl_extcfg_mod_intf(index, INTERFACE_ADD);
	}

	ret = rtl_config_bss_wdev(cfg, index);
	if (ret)
#ifdef Q_OPENWRT
		qcsapi_qwe_command("qweaction", "wlan1", "commit", NULL, qwecfg_output, QWECFG_OUTPUT_MAX);
#else
		system("qweaction wlan1 commit");
#endif

	return 0;
}

static int rtl_get_index_by_ifname(char *ifname)
{
	if (strncmp("wlan0-va", ifname, 8)==0)
		return (atoi(&ifname[8])+1);
	if (strcmp("wlan0", ifname)==0)
		return 0;
	return -1;
}


static int rtl_extcfg_del_wdev(char *vap_name)
{
	int index = rtl_get_index_by_ifname(vap_name);
#ifdef Q_OPENWRT
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
#endif

	if (index >= 0) {
		rtl_enable_wdev(index, 0);
		rtl_extcfg_mod_intf(index,INTERFACE_DEL);
#ifdef Q_OPENWRT
		qcsapi_qwe_command("qweaction", "wlan1", "commit", NULL, qwecfg_output, QWECFG_OUTPUT_MAX);
#else
		system("qweaction wlan1 commit");
#endif
		return 0;
	} else {
		EXTCFG_ERROR("rtl_extcfg_del_wdev:: the VAP[%s] is NOT exist.\n", vap_name);
		return -1;
	}
}

static int rtl_extcfg_cfg_wdev(struct blob_attr **tb, char *ifname)
{
	int ret;
	int index = rtl_get_index_by_ifname(ifname);
#ifdef Q_OPENWRT
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
#endif

	if (index < 0) {
		EXTCFG_ERROR("can not find ifname %s\n", ifname);
		return -1;
	}
	ret = rtl_config_bss_wdev(tb, index);
	if (ret)
#ifdef Q_OPENWRT
		qcsapi_qwe_command("qweaction", "wlan1", "commit", NULL, qwecfg_output, QWECFG_OUTPUT_MAX);
#else
		system("qweaction wlan1 commit");
#endif

	return 0;
}

static void rtl_extcfg_get_bsscfg(char *ifname)
{
	int index = rtl_get_index_by_ifname(ifname);
	int len_value = 0;
	char param[32];
	char value[64];
	uint32_t auth = MAP_IEEE80211_AUTH_MODE_OPEN;
	uint32_t encrypt = MAP_IEEE80211_ENCRYP_MODE_NONE;
	char print_str[128] = {0};

	if (index < 0) {
		EXTCFG_ERROR("can not find ifname %s\n", ifname);
		return;
	}

	memset(param, 0, 32);
	memset(value, 0, 64);
	sprintf(param, "encryption.%s", rtl_config_ifnames[index]);
	if (rtl_qwecfg_get(param, strlen(param), value, &len_value,
				PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG) < 0) {
		EXTCFG_ERROR("rtl_qwecfg_get %s failed\n", param);
	}
	else {
		sprintf(print_str, "auth_encrypt(%s)", value);
		if (!strcmp(value, "mixed") || !strncmp(value, "wpa2", 4)) {
			auth = MAP_IEEE80211_AUTH_MODE_WPA2PSK;
			encrypt = MAP_IEEE80211_ENCRYP_MODE_AES;
		}
		else if (!strncmp(value, "wpa", 3)) {
			auth = MAP_IEEE80211_AUTH_MODE_WPAPSK;
			encrypt = MAP_IEEE80211_ENCRYP_MODE_TKIP;
		}
		else if (!strcmp(value, "open")) {
			auth = MAP_IEEE80211_AUTH_MODE_OPEN;
			encrypt = MAP_IEEE80211_ENCRYP_MODE_NONE;
		}
		else {
			EXTCFG_ERROR("auth/encrypt mode unsupport, %s=%s\n", param, value);
		}
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_AUTH_NAME, auth);
		blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_ENCRYP_NAME, encrypt);
	}

	memset(param, 0, 32);
	memset(value, 0, 64);
	sprintf(param, "ssid.%s", rtl_config_ifnames[index]);
	if (rtl_qwecfg_get(param, strlen(param), value, &len_value,
				PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG) < 0) {
		EXTCFG_ERROR("rtl_qwecfg_get %s failed\n", param);
	}
	else {
		sprintf(print_str+strlen(print_str), " SSID(%s)", value);
		blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_SSID_NAME,
				(void *)value, len_value);
	}

	if (auth != MAP_IEEE80211_AUTH_MODE_OPEN) {
		memset(param, 0, 32);
		memset(value, 0, 64);
		sprintf(param, "passphrase.%s", rtl_config_ifnames[index]);
		if (rtl_qwecfg_get(param, strlen(param), value, &len_value,
					PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG) < 0) {
			EXTCFG_ERROR("rtl_qwecfg_get %s failed\n", param);
		}
		else {
			sprintf(print_str+strlen(print_str), " key(%s)", value);
			blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_KEY_NAME,
					(void *)value, len_value);
		}
	}

	/*ignore mtype for 2.4G interfaces */

	EXTCFG_DEBUG("get original configurations of interface(%s): %s\n",
			ifname, print_str);
}

static int qtn_extcfg_get_primary_ifname(char *radio_ifname, char *primary_ifname)
{
	qcsapi_wifi_mode dev_mode;

	if (qcsapi_wifi_get_mode(radio_ifname, &dev_mode) < 0)
		return -1;

	strncpy(primary_ifname, radio_ifname, IFNAME_MAXLEN);
	if (dev_mode != qcsapi_access_point)
		primary_ifname[strlen(primary_ifname) - 1] = '1';

	return 0;
}

static int qtn_extcfg_find_available_ifname(int mode, char *radio_ifname,
		char *ifname, bool *is_primary)
{
	char ind = '0';
	int ret = 0;
	qcsapi_SSID tmp_ssid;
	char primary_ifname[IFNAME_MAXLEN + 1] = { 0 };
	char status[10] = { '\0' };

	if (!ifname)
		return -1;

	// Check primary interface available for AP mode
	if (mode == MAP_INTERFACE_TYPE_AP) {
		if (qtn_extcfg_get_primary_ifname(radio_ifname, primary_ifname) < 0) {
			ret = -1;
			goto find_done;
		}
		if (qcsapi_interface_get_status(primary_ifname, status) < 0) {
			ret = -1;
			goto find_done;
		}
		if (!strcmp(status, "Disabled")) {
			strncpy(ifname, primary_ifname, IFNAME_MAXLEN);
			if (is_primary)
				*is_primary = true;
			ret = 0;
			goto find_done;
		}
	}

	strcpy(ifname, radio_ifname);

	do {
		ind++;
		ifname[strlen(ifname) - 1] = ind;
	} while((qcsapi_wifi_get_SSID(ifname, tmp_ssid) == 0));

	if (ind >= '8')
		ret = -1;
find_done:
	return ret;
}

static int qtn_extcfg_check_backhaul_bss(
	char *ifname, char *ifssid, char *ifkey)
{
	char ind = '0';
	qcsapi_SSID tmp_ssid = {0};
	string_64 tmp_key = {0};
	char tmp_name[IFNAME_MAXLEN + 1] = {0};
	strncpy(tmp_name, ifname, IFNAME_MAXLEN);

	for (ind = '0'; ind < '8'; ind++) {
		tmp_name[strlen(ifname) - 1] = ind;
		if (qcsapi_wifi_get_bss_cfg(tmp_name, qcsapi_access_point, tmp_name,
					"multiap_backhaul_bss_ssid", tmp_ssid, sizeof(tmp_ssid)) < 0)
			continue;

		if (qcsapi_wifi_get_bss_cfg(tmp_name, qcsapi_access_point, tmp_name,
					"multiap_backhaul_bss_wpa_passphrase", tmp_key, sizeof(tmp_key)) < 0)
			continue;

		if (strcmp(tmp_ssid, ifssid) == 0 &&
				strcmp(tmp_key, ifkey) == 0)
			return 1;
		else
			return 0;
	}
	return 0;
}

static int qtn_extcfg_check_intf_removable(char *ifname)
{
	qcsapi_wifi_mode mode;
	char ind = ifname[strlen(ifname) - 1];

#ifdef SPARTAN_PLATFORM
	if (ind == '0' || ind == BBSS_IF_IDX_CHAR )
#else
	if (ind == '0')
#endif
		return 0;
	else if (ind == '1') {
		char radio_ifname[IFNAME_MAXLEN + 1] = {0};
		strncpy(radio_ifname, ifname, IFNAME_MAXLEN);
		radio_ifname[strlen(ifname) - 1] = '0';
		qcsapi_wifi_get_mode(radio_ifname, &mode);
		if (mode == qcsapi_station)
			return 0;
	}

	return 1;
}

static void qtn_apply_config_defer_mode(const char* ifname)
{
	int defer_mode = 0, ret = 0;
	char pri_if[IFNAME_MAXLEN + 1] = {0};

	/* for Spartan Essential which defer mode is enabled by default */
	ret = qcsapi_get_primary_interface(pri_if, sizeof(pri_if));
	if (!ret)
		ret = qcsapi_wifi_get_security_defer_mode(pri_if, &defer_mode);
	if (!ret && defer_mode) {
		qcsapi_wifi_apply_security_config(ifname);
		EXTCFG_DEBUG("apply security config for interface %s\n", ifname);
	}
}

#ifdef SPARTAN_PLATFORM
static int is_vif_backhaul(const char* vif)
{
	//return (!strcmp(vif, UCI_BBSS_IF_R0) || !strcmp(vif, UCI_BBSS_IF_R1));
	return (!strcmp(vif, UCI_BBSS_IF_R0));
}

static int update_if_uuid(const char* ifname)
{
	int ret = 0;
	char ap_if[8] = {'\0'}, uuid[64] = {'\0'};

	ret = qcsapi_wifi_get_ap_interface_name(ap_if);
	if (ret < 0)
		return ret;

	ret = qcsapi_wifi_get_bss_cfg(ap_if, qcsapi_access_point, ap_if,
				"uuid", uuid, sizeof(uuid));
	if (ret < 0) {
		EXTCFG_ERROR("'call_qcsapi get_bss_cfg %s ap %s uuid' failed, ret: %d\n",
				ap_if, ap_if, ret);
		return ret;
	}

	ret = qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
				"uuid", uuid, NULL);
	if (ret < 0) {
		EXTCFG_ERROR("'call_qcsapi update_bss_cfg %s ap %s uuid %s' failed, ret: %d\n",
				ifname, ifname, uuid, ret);
		return ret;
	}

	return ret;
}
#endif

static int qtn_extcfg_add_intf(struct blob_attr **info, const char* radio_ifname, const char* ifname)
{
	int ret = 0, defer_mode = 0, defer_disabled = 0;
	char pri_if[IFNAME_MAXLEN + 1] = {0};
	qcsapi_SSID tmp_ssid;

	if (qcsapi_wifi_get_SSID(ifname, tmp_ssid) == 0)
		return -1;

	uci_wifi_mod_intf(ifname, INTERFACE_ADD);

	/* for Spartan Essential which defer mode is enabled by default */
	ret = qcsapi_get_primary_interface(pri_if,  sizeof(pri_if));
	if (!ret)
		ret = qcsapi_wifi_get_security_defer_mode(pri_if, &defer_mode);
	if (!ret && defer_mode) {
		qcsapi_wifi_set_security_defer_mode(pri_if, 0);
		defer_disabled = 1;
	}

	ret = qcsapi_wifi_create_bss(ifname, NULL);

#ifdef SPARTAN_PLATFORM
	ret |= update_if_uuid(ifname);
#endif

	if (defer_disabled)
		qcsapi_wifi_set_security_defer_mode(pri_if, 1);

	return ret;
}

static int qtn_extcfg_del_intf(const char* ifname)
{
	int ret = 0, defer_mode = 0, defer_disabled = 0;
	char pri_if[IFNAME_MAXLEN + 1] = {0};
	qcsapi_SSID tmp_ssid;
#ifdef SPARTAN_PLATFORM
	char status[10] = { '\0' };
	char vif[IFNAME_MAXLEN + 1] = {0};
#endif

	if (qcsapi_wifi_get_SSID(ifname, tmp_ssid) != 0)
		return 0;

#ifdef SPARTAN_PLATFORM
	ret = ifname_to_virtual(ifname, vif, sizeof(vif));
	qcsapi_interface_get_status(ifname, status);
	if (!strcmp(status, "Up") && is_vif_backhaul(vif)) {
		qcsapi_interface_enable(ifname, 0);
		// UCI_SET_WIRELESS_IF_INT(vif, "enable", 1);
		EXTCFG_DEBUG("disable backhaul interface ifname:%s\n", ifname);
	}
#endif

	/* for Spartan Essential which defer mode is enabled by default */
	ret = qcsapi_get_primary_interface(pri_if, sizeof(pri_if));
	if (!ret)
		ret = qcsapi_wifi_get_security_defer_mode(pri_if, &defer_mode);
	if (!ret && defer_mode) {
		qcsapi_wifi_set_security_defer_mode(pri_if, 0);
		defer_disabled = 1;
	}

	uci_wifi_mod_intf(ifname, INTERFACE_DEL);

	ret = qcsapi_wifi_remove_bss(ifname);

	if (defer_disabled)
		qcsapi_wifi_set_security_defer_mode(pri_if, 1);

	return ret;
}

static void qtn_extcfg_delete_removable_intfs(char *radio_ifname,
	char start_ind)
{
	char ind, status[10] = {0}, ifname[IFNAME_MAXLEN + 1] = {0};

	strncpy(ifname, radio_ifname, IFNAME_MAXLEN);

#ifdef SPARTAN_PLATFORM
	for (ind = start_ind; ind < BBSS_IF_IDX_CHAR ; ind++) {
#else
	for (ind = start_ind; ind < '8'; ind++) {
#endif
		ifname[strlen(ifname) - 1] = ind;
		if (qcsapi_interface_get_status(ifname, status) == 0)
			qtn_extcfg_del_intf(ifname);
	}
}

static void qtn_extcfg_disable_intf(char *ifname)
{
	int ret = qcsapi_interface_enable(ifname, 0);
	// UCI_SET_WIRELESS_IF_INT(ifname, "enable", 0);
	if (ret != 0)
		EXTCFG_ERROR("disable %s intf failed!\n",ifname);
}

static int qtn_extcfg_create_wdev(struct blob_attr **info,
	char *radio_ifname, char *ifname)
{
	int ret = -1, mode;
	bool is_primary = false;
#ifdef SPARTAN_PLATFORM
    int bBss = 0;
	qcsapi_SSID tmp_ssid;
	char status[10] = { '\0' };
	int  radio_ind = 0, vap_ind = 0, mtype = 0;
	char vif[IFNAME_MAXLEN + 1] = {0};
#endif

	if (!info[MAP_EXTCFG_ATTR_MODE])
		return ret;

	mode = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_MODE]);

	if (qtn_extcfg_find_available_ifname(mode, radio_ifname, ifname, &is_primary) < 0) {
		EXTCFG_ERROR("no available MBSSID to create\n");
		return ret;
	}

#ifdef SPARTAN_PLATFORM
	if (info[MAP_EXTCFG_ATTR_MAP_TYPES]) {
		mtype = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_MAP_TYPES]);
		bBss = mtype & MAP_MTYPE_BACKHAUL_BSS;
	}
	if (bBss && (mode == MAP_INTERFACE_TYPE_AP)) {
		ret = sscanf(radio_ifname, "wifi%d_%d", &radio_ind, &vap_ind);
		if ((ret == 2 && radio_ind == 2) || (ret == 0))
			radio_ind = 1;

		snprintf(vif, sizeof(vif), "r%dvap%d", radio_ind, BBSS_IF_IDX);
		virtual_to_ifname(ifname, vif, sizeof(vif));

		if (qcsapi_wifi_get_SSID(ifname, tmp_ssid) == 0) {
			ret = qcsapi_interface_get_status(ifname, status);
			if (!ret && !strcmp(status, "Disabled")) {
				qcsapi_interface_enable(ifname, 1);
				// UCI_SET_WIRELESS_IF_INT(vif, "enable", 1);
				EXTCFG_DEBUG("enable backhaul interface ifname:%s\n", ifname);
			}
			return 0;
		}
		goto create_intf;
	}
#endif

	if (is_primary) {
		EXTCFG_DEBUG("Not to create new intf, re-configure %s!\n", ifname);
		qcsapi_interface_enable(ifname, 1);
		// UCI_SET_WIRELESS_IF_INT(second_ifname, "enable", 1);
		return 0;
	}
#ifdef SPARTAN_PLATFORM
create_intf:
#endif
	ret = qtn_extcfg_add_intf(info, radio_ifname, ifname);
	if (mode == MAP_INTERFACE_TYPE_STATION) {
#ifdef SPARTAN_PLATFORM
		EXTCFG_DEBUG("device should be reloaded by Backhaul Manager instead of MAP\n");
		ret = -1;
#else
		ret |= qcsapi_wifi_reload_in_mode(ifname, qcsapi_station);
#endif
	}
	else if (mode != MAP_INTERFACE_TYPE_AP)
		EXTCFG_ERROR("unallowable mode type [%d] to configure!\n", mode);

	if (ret != 0)
		EXTCFG_ERROR("create %s wdev failed!\n",ifname);

	return ret;
}

static void qtn_extcfg_delete_wdev(char *ifname)
{
	int ret;
	ret = qtn_extcfg_del_intf(ifname);
	if (ret != 0)
		EXTCFG_ERROR("delete %s wdev failed!\n",ifname);
}

static int is_ifname_backhaul(const char* ifname)
{
#ifdef SPARTAN_PLATFORM
	uint32_t ret = 0;
	char vif[IFNAME_MAXLEN + 1] = {0};

	ret = ifname_to_virtual(ifname, vif, sizeof(vif));

	return !ret && is_vif_backhaul(vif);
#else
	return 0;
#endif
}

static void qtn_qcsapi_config_bss_wdev(struct blob_attr **info, char *ifname)
{
	uint8_t *tmp_data;
	uint32_t tmp_data_len, auth = 0, encryp = 0, wps;
#ifdef SPARTAN_PLATFORM
    uint32_t ret = 0;
#endif
    uint32_t bh = is_ifname_backhaul(ifname);
	bool configured = false;


//disable defer mode as bbic5 has issue
#if 0
	char radio_ifname[IFNAME_MAXLEN + 1] = {0};

	strncpy(radio_ifname, ifname, IFNAME_MAXLEN);
	radio_ifname[strlen(ifname) - 1] = '0';

	qcsapi_wifi_set_security_defer_mode(radio_ifname, 1);
#endif
	if (info[MAP_EXTCFG_ATTR_SSID]) {
		uint8_t ssid[SSID_MAXLEN + 1];
		tmp_data = blobmsg_data(info[MAP_EXTCFG_ATTR_SSID]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_ATTR_SSID]);
		if (tmp_data_len > SSID_MAXLEN) {
			EXTCFG_ERROR("ssid %s of len[%d] exceeds the max allowable length[%d]\n",
				tmp_data, tmp_data_len, SSID_MAXLEN);
			return;
		}
		memcpy(ssid, tmp_data, tmp_data_len);
		ssid[tmp_data_len] = '\0';
		qcsapi_wifi_set_SSID(ifname, (char *)ssid);
		UCI_SET_WIRELESS_IF_STR(ifname, "ssid", (char *)ssid);
		if (bh)
			UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, "sta", "ssid", (char *)ssid, ret);
		configured = true;
	}

	if (info[MAP_EXTCFG_ATTR_AUTH]) {
		auth = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_AUTH]);
		if (auth == MAP_IEEE80211_AUTH_MODE_OPEN) {
			qcsapi_wifi_set_beacon_type(ifname, "Basic");
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA) {
			qcsapi_wifi_set_beacon_type(ifname, "WPA");
			qcsapi_wifi_set_WPA_authentication_mode(ifname,
				"EAPAuthentication");
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPAPSK) {
			qcsapi_wifi_set_beacon_type(ifname, "WPA");
			qcsapi_wifi_set_WPA_authentication_mode(ifname,
				"PSKAuthentication");
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA2) {
			qcsapi_wifi_set_beacon_type(ifname, "11i");
			qcsapi_wifi_set_WPA_authentication_mode(ifname,
				"EAPAuthentication");
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA2PSK) {
			qcsapi_wifi_set_beacon_type(ifname, "11i");
			qcsapi_wifi_set_WPA_authentication_mode(ifname,
				"PSKAuthentication");
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_SHARED)
			EXTCFG_ERROR("Pre-shared WEP key is obsolete - not support\n");
		else
			EXTCFG_ERROR("unknown auth type :0x04%x\n", auth);
		configured = true;
	}

	if (info[MAP_EXTCFG_ATTR_ENCRYP]) {
		encryp = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_ENCRYP]);
		if(encryp == MAP_IEEE80211_ENCRYP_MODE_NONE &&
			auth != MAP_IEEE80211_AUTH_MODE_OPEN)
			EXTCFG_ERROR("cipher mode none is only allowed at open auth mode\n");
		else if (encryp == MAP_IEEE80211_ENCRYP_MODE_TKIP)
			qcsapi_wifi_set_WPA_encryption_modes(ifname, "TKIPEncryption");
		else if (encryp == MAP_IEEE80211_ENCRYP_MODE_AES)
			qcsapi_wifi_set_WPA_encryption_modes(ifname, "AESEncryption");
		else if (encryp == MAP_IEEE80211_ENCRYP_MODE_WEP)
			EXTCFG_ERROR("Pre-shared WEP key is obsolete - not support\n");
		else if (encryp != MAP_IEEE80211_ENCRYP_MODE_NONE)
			EXTCFG_ERROR("unknown encryp type :0x04%x\n", encryp);
		configured = true;
	}

	UCI_SET_WIFI_SECURITY(ifname, NULL, auth, encryp);
	if (bh)
		UCI_SET_WIFI_SECURITY(NULL, "sta", auth, encryp);

	if (info[MAP_EXTCFG_ATTR_KEY]) {
		char key[KEY_MAXLEN + 1];
		tmp_data = blobmsg_data(info[MAP_EXTCFG_ATTR_KEY]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_ATTR_KEY]);
		if (tmp_data_len > KEY_MAXLEN) {
			EXTCFG_ERROR("key len[%d] exceeds the max allowable length[%d]\n",
				tmp_data_len, KEY_MAXLEN);
			return;
		}
		memcpy(key, tmp_data, tmp_data_len);
		key[tmp_data_len] = '\0';
		if (tmp_data_len < KEY_MAXLEN) {
			qcsapi_wifi_set_key_passphrase(ifname, 0, key);
			EXTCFG_DEBUG("set key passphrase %s\n", key);
		} else {
			qcsapi_wifi_set_pre_shared_key(ifname, 0, key);
			EXTCFG_DEBUG("set key pre-shared-key %s\n", key);
		}
		UCI_SET_WIRELESS_IF_STR(ifname, "key", key);
		if (bh)
			UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, "sta", "key", (char *)key, ret);
		configured = true;
	}

	if (info[MAP_EXTCFG_ATTR_WPS]) {
		wps = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_WPS]);
		qcsapi_wifi_disable_wps(ifname, !wps);
		/* TODO: No WPS UCI flag currently */
		EXTCFG_DEBUG("%sable the wps for %s\n", wps ? "en" : "dis", ifname);
		configured = true;
	}

	if (info[MAP_EXTCFG_ATTR_4ADDR]) {
		uint32_t enable_4addr = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_4ADDR]);
		int cfg_4addr = IEEE80211_CFG_4ADDR_MODE_DISABLE;
		if (enable_4addr)
			cfg_4addr = IEEE80211_CFG_4ADDR_MODE_ENABLE_AMSDU;
		CALL_QCSAPI_SET_WIFI_PARAM(ifname, qcsapi_wifi_param_cfg_4addr, cfg_4addr);
	}

	if (info[MAP_EXTCFG_ATTR_HIDE_SSID]) {
		/*int be_broadcasting = 0;
		uint32_t hide_ssid = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_HIDE_SSID]);
		qcsapi_wifi_get_option(ifname, qcsapi_SSID_broadcast, &be_broadcasting);
		if (hide_ssid && be_broadcasting)
			qcsapi_wifi_set_option(ifname, qcsapi_SSID_broadcast, 0);
		else if (!hide_ssid && !be_broadcasting)
			qcsapi_wifi_set_option(ifname, qcsapi_SSID_broadcast, 1);*/

		/* hidden need to be disabled for multi-hop feature.
		 * if there is two AP in different DFS channel with hidden backhaul,
		 * the repeater can only clear onw DFS channel that it is already at,
		 * the repeater may never send probe request for hidden aps in other DFS channel.
		 * then repeater have no chance to associate with others aps in ther DFS channel */
		qcsapi_wifi_set_option(ifname, qcsapi_SSID_broadcast, 1);
		configured = true;
		//UCI_SET_WIRELESS_IF_INT(ifname, "hidden", 0);
		//if (bh)
			//UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, "sta", "hidden", 0, ret);
	}
//disable defer mode as bbic5 has issue
#if 0

	qcsapi_wifi_set_security_defer_mode(radio_ifname, 0);
	qcsapi_wifi_apply_security_config(ifname);
#endif
	if (configured)
		qtn_apply_config_defer_mode(ifname);
}

static void qtn_qcsapi_config_sta_wdev(struct blob_attr **info, char *ifname)
{
	int ret;
	qcsapi_SSID cur_ssid;
	uint8_t *tmp_data;
	uint32_t tmp_data_len, auth = 0, encryp = 0, wps;
	char ssid[SSID_MAXLEN + 1] = { 0 };
	bool configured = false;

	if (info[MAP_EXTCFG_ATTR_SSID]) {
		tmp_data = blobmsg_data(info[MAP_EXTCFG_ATTR_SSID]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_ATTR_SSID]);
		if (tmp_data_len > SSID_MAXLEN) {
			EXTCFG_ERROR("ssid %s of len[%d] exceeds the max allowable length[%d]\n",
				tmp_data, tmp_data_len, SSID_MAXLEN);
			return;
		}

		memcpy(ssid, tmp_data, tmp_data_len);
		memset(cur_ssid, 0, sizeof(cur_ssid));
		if (qcsapi_wifi_get_SSID(ifname, cur_ssid) >= 0 &&
			cur_ssid[0] != 0 && strcmp(cur_ssid, ssid) != 0)
				qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station,
					cur_ssid, "ssid", ssid, NULL);
		else
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"ssid", ssid, NULL);
		configured = true;
		UCI_SET_WIRELESS_IF_STR(ifname, "ssid", ssid);
	}

	if (info[MAP_EXTCFG_ATTR_AUTH]) {
		auth = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_AUTH]);
		if (auth == MAP_IEEE80211_AUTH_MODE_OPEN) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"key_mgmt", "NONE", NULL);
			configured = true;
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"key_mgmt", "WPA-EAP", NULL);
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"proto", "WPA", NULL);
			configured = true;
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPAPSK) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"key_mgmt", "WPA-PSK", NULL);
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"proto", "WPA", NULL);
			configured = true;
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA2) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"key_mgmt", "WPA-EAP", NULL);
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"proto", "WPA2", NULL);
			configured = true;
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA2PSK) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"key_mgmt", "WPA-PSK", NULL);
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"proto", "WPA2", NULL);
			configured = true;
		}
		else if (auth == MAP_IEEE80211_AUTH_MODE_SHARED)
			EXTCFG_ERROR("Pre-shared WEP key is obsolete - not support\n");
		else
			EXTCFG_ERROR("unknown auth type :0x04%x\n", auth);
	}

	if (info[MAP_EXTCFG_ATTR_ENCRYP]) {
		encryp = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_ENCRYP]);
		if(encryp == MAP_IEEE80211_ENCRYP_MODE_NONE &&
			auth != MAP_IEEE80211_AUTH_MODE_OPEN)
			EXTCFG_ERROR("cipher mode none is only allowed at open auth mode\n");
		else if (encryp == MAP_IEEE80211_ENCRYP_MODE_TKIP) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"pairwise", "TKIP", NULL);
			configured = true;
		}
		else if (encryp == MAP_IEEE80211_ENCRYP_MODE_AES) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid,
				"pairwise", "CCMP", NULL);
			configured = true;
		}
		else if (encryp == MAP_IEEE80211_ENCRYP_MODE_WEP)
			EXTCFG_ERROR("Pre-shared WEP key is obsolete - not support\n");
		else
			EXTCFG_ERROR("unknown encryp type :0x04%x\n", encryp);
	}

	UCI_SET_WIFI_SECURITY(ifname, NULL, auth, encryp);

	if (info[MAP_EXTCFG_ATTR_KEY]) {
		char key[KEY_MAXLEN + 1];
		tmp_data = blobmsg_data(info[MAP_EXTCFG_ATTR_KEY]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_ATTR_KEY]);
		if (tmp_data_len > KEY_MAXLEN) {
			EXTCFG_ERROR("key len[%d] exceeds the max allowable length[%d]\n",
				tmp_data_len, KEY_MAXLEN);
			return;
		}
		memcpy(key, tmp_data, tmp_data_len);
		key[tmp_data_len] = '\0';
		qcsapi_wifi_update_bss_cfg(ifname, qcsapi_station, ssid, "psk",
			key, "1");
		configured = true;
		UCI_SET_WIRELESS_IF_STR(ifname, "key", key);
	}

	if (info[MAP_EXTCFG_ATTR_WPS]) {
		wps = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_WPS]);
		qcsapi_wifi_disable_wps(ifname, !wps);
		/* TODO: UCI does not have WPS flag currently */
		EXTCFG_DEBUG("%sable the wps for %s\n", wps ? "en" : "dis", ifname);
	}

	if (info[MAP_EXTCFG_ATTR_4ADDR]) {
		uint32_t enable_4addr = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_4ADDR]);
		int cfg_4addr = IEEE80211_CFG_4ADDR_MODE_DISABLE;
		if (enable_4addr)
			cfg_4addr = IEEE80211_CFG_4ADDR_MODE_ENABLE_AMSDU;
		CALL_QCSAPI_SET_WIFI_PARAM(ifname, qcsapi_wifi_param_cfg_4addr, cfg_4addr);
	}

	if (configured) {
		/* TODO: the configuration changed check via qcsapi_wifi_get_bss_cfg */
		ret = qcsapi_wifi_apply_security_config(ifname);
		if (ret != 0)
			EXTCFG_ERROR("apply the configuration for backhal sta failed!\n");
	}
}


static void qtn_extcfg_config_wdev(struct blob_attr **info, char *ifname)
{
	qcsapi_wifi_mode mode;
	int disable_intf;
	char status[10] = { '\0' };

	qcsapi_wifi_get_mode(ifname, &mode);
	if (mode == qcsapi_station)
		qtn_qcsapi_config_sta_wdev(info, ifname);
	else if (mode == qcsapi_access_point)
		qtn_qcsapi_config_bss_wdev(info, ifname);

	if (info[MAP_EXTCFG_ATTR_DISABLE]) {
		disable_intf = blobmsg_get_u32(info[MAP_EXTCFG_ATTR_DISABLE]);
		if (qcsapi_interface_get_status(ifname, status) == 0) {
			if (strcmp(status, "Up") == 0 && disable_intf == 1) {
				qcsapi_interface_enable(ifname, 0);
				// UCI_SET_WIRELESS_IF_INT(ifname, "enable", 0);
			}
			else if (strcmp(status, "Disabled") == 0 && disable_intf == 0) {
				qcsapi_interface_enable(ifname, 1);
				// UCI_SET_WIRELESS_IF_INT(ifname, "enable", 1);
			}
		}
	}
}

static void qtn_extcfg_reset_backhaul(char *ifname);
static void qtn_extcfg_config_backhaul(struct blob_attr **info, char *ifname)
{
	int ret;
	qcsapi_wifi_mode mode;
	uint8_t *tmp_data;
	uint32_t tmp_data_len, auth;
	char tmp_buf[64];
#ifdef SPARTAN_PLATFORM
    char vif[IFNAME_MAXLEN + 1] = {0};
	char vif_bbss[IFNAME_MAXLEN + 1] = {0};
	char ifname_bbss[IFNAME_MAXLEN + 1] = {0};
	ret = 0;
#endif

	qcsapi_wifi_get_mode(ifname, &mode);
	if (mode != qcsapi_access_point)
		return;

	// Reset backhaul configuration when get NULL table
	if (!info[MAP_EXTCFG_BACKHAUL_ATTR_SSID] &&
			!info[MAP_EXTCFG_BACKHAUL_ATTR_AUTH] &&
			!info[MAP_EXTCFG_BACKHAUL_ATTR_KEY]) {
		qtn_extcfg_reset_backhaul(ifname);
		return;
	}

	EXTCFG_DEBUG("start to set the backhaul configuration for %s\n", ifname);

#ifdef SPARTAN_PLATFORM
	ret = ifname_to_virtual(ifname, vif, sizeof(vif));
	if (ret)
		return;

	strncpy(ifname_bbss, ifname, IFNAME_MAXLEN);
	ifname_bbss[strlen(ifname_bbss) - 1] = BBSS_IF_IDX_CHAR;
	ifname_to_virtual(ifname_bbss, vif_bbss, sizeof(vif_bbss));
#endif

	qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
				"wps_cred_processing_multiap_backhaul", "1", NULL);
	UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, vif, UCI_OPT_MAP_BBSS, vif_bbss, ret);

	if (info[MAP_EXTCFG_BACKHAUL_ATTR_SSID]) {
		tmp_data = blobmsg_data(info[MAP_EXTCFG_BACKHAUL_ATTR_SSID]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_BACKHAUL_ATTR_SSID]);
		if (tmp_data_len > SSID_MAXLEN) {
			EXTCFG_ERROR("ssid %s of len[%d] exceeds the max allowable length[%d]\n",
				tmp_data, tmp_data_len, SSID_MAXLEN);
			return;
		}
		memcpy(tmp_buf, tmp_data, tmp_data_len);
		tmp_buf[tmp_data_len] = '\0';
		qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
				"multiap_backhaul_bss_ssid", tmp_buf, NULL);
		UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, vif_bbss, "ssid", tmp_buf, ret);
	}

	if (info[MAP_EXTCFG_BACKHAUL_ATTR_AUTH]) {
		auth = blobmsg_get_u32(info[MAP_EXTCFG_BACKHAUL_ATTR_AUTH]);
		tmp_buf[0] = '\0';
		if (auth == MAP_IEEE80211_AUTH_MODE_WPAPSK)
			strcpy(tmp_buf, "WPA-PSK");
		else if (auth == MAP_IEEE80211_AUTH_MODE_WPA2PSK)
			strcpy(tmp_buf, "WPA2-PSK");

		if (strlen(tmp_buf) > 0) {
			qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
				"multiap_backhaul_bss_wpa_psk", tmp_buf, NULL);
			UCI_SET_WIFI_SECURITY(NULL, vif_bbss, auth, MAP_IEEE80211_ENCRYP_MODE_AES);
		}
	}

	if (info[MAP_EXTCFG_BACKHAUL_ATTR_KEY]) {
		tmp_data = blobmsg_data(info[MAP_EXTCFG_BACKHAUL_ATTR_KEY]);
		tmp_data_len = blobmsg_data_len(info[MAP_EXTCFG_BACKHAUL_ATTR_KEY]);
		if (tmp_data_len > KEY_MAXLEN) {
			EXTCFG_ERROR("key len[%d] exceeds the max allowable length[%d]\n",
				tmp_data_len, KEY_MAXLEN);
			return;
		}
		memcpy(tmp_buf, tmp_data, tmp_data_len);
		tmp_buf[tmp_data_len] = '\0';
		qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
				"multiap_backhaul_bss_wpa_passphrase", tmp_buf, NULL);
		UCI_SET_OPTION_STR(UCI_PKG_WIRELESS, vif_bbss, "key", tmp_buf, ret);
	}

	ret = qcsapi_wifi_apply_security_config(ifname);
	if (ret != 0)
		EXTCFG_ERROR("apply the backhaul configuration for fronthaul BSS failed!\n");
}

static void qtn_extcfg_reset_backhaul(char *ifname)
{
	EXTCFG_DEBUG("start to reset the backhaul configuration for %s\n", ifname);

	qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
			"wps_cred_processing_multiap_backhaul", "NULL", NULL);

	qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
			"multiap_backhaul_bss_ssid", "NULL", NULL);

	qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
			"multiap_backhaul_bss_wpa_psk", "NULL", NULL);

	qcsapi_wifi_update_bss_cfg(ifname, qcsapi_access_point, ifname,
			"multiap_backhaul_bss_wpa_passphrase", "NULL", NULL);

	qtn_apply_config_defer_mode(ifname);
	UCI_SET_WIRELESS_IF_STR(ifname, UCI_OPT_MAP_BBSS, "");
}

static void qtn_extcfg_disable_unremovable_wdev(char *ifname)
{
	qcsapi_wifi_mode mode;
	qcsapi_wifi_get_mode(ifname, &mode);
	if (mode != qcsapi_access_point)
		return;

	qtn_extcfg_reset_backhaul(ifname);
	qtn_extcfg_disable_intf(ifname);
}

static int qtn_extcfg_cfg_wiphy(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAP_EXTCFG_WIPHY_ATTRS];
	qcsapi_wifi_mode mode;
	char *radio_ifname, start_ind = '1';
	char second_ifname[IFNAME_MAXLEN + 1] = { 0 };
#ifdef Q_OPENWRT
	char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};
#endif
#ifdef SPARTAN_PLATFORM
	char status[10] = {0};
#endif

	blobmsg_parse(extcfg_wiphy_policy, NUM_MAP_EXTCFG_WIPHY_ATTRS,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_EXTCFG_WIPHY_ATTR_WIPHY] || !tb[MAP_EXTCFG_WIPHY_ATTR_TEARDOWN]) {
		EXTCFG_ERROR("Failed to cfg radio: missing attr\n");
		return -1;
	}

	radio_ifname = (char *) blobmsg_get_string(tb[MAP_EXTCFG_WIPHY_ATTR_WIPHY]);

	if (blobmsg_get_u32(tb[MAP_EXTCFG_WIPHY_ATTR_TEARDOWN]) == 1) {
		if (!memcmp(radio_ifname, "wlan0", strlen("wlan0"))) {
			rtl_extcfg_disable_radio();
#ifdef Q_OPENWRT
			qcsapi_qwe_command("qweaction", "wlan1", "commit", NULL, qwecfg_output, QWECFG_OUTPUT_MAX);
#else
			system("qweaction wlan1 commit");
#endif
		}
		else {
			char *disable_ifname = radio_ifname;
			qcsapi_wifi_get_mode(radio_ifname, &mode);
			if (mode == qcsapi_station) {
				strncpy(second_ifname, radio_ifname, IFNAME_MAXLEN);
				second_ifname[strlen(second_ifname) - 1] = '1';
				disable_ifname = second_ifname;
				start_ind = '2';
			}
			/* Note: On BBIC5 platform, It should first remove other interface,
			 * Then disable the primary interface. otherwise, the wrong sequence
			 * will result in Panic */
			qtn_extcfg_delete_removable_intfs(radio_ifname, start_ind);
			qtn_extcfg_disable_unremovable_wdev(disable_ifname);
#ifdef SPARTAN_PLATFORM
			/* disable backhaul interface rxvap7 */
			disable_ifname[strlen(disable_ifname) - 1] = BBSS_IF_IDX_CHAR;
			if (qcsapi_interface_get_status(disable_ifname, status) == 0)
				qtn_extcfg_disable_intf(disable_ifname);
#endif
		}
	}
	return 0;
}

static void qtn_extcfg_active_wps(char *ifname)
{
	qcsapi_wifi_mode mode;

	qcsapi_wifi_get_mode(ifname, &mode);
	if (mode == qcsapi_access_point) {
		EXTCFG_DEBUG("WPS is started at AP interface:%s\n", ifname);
		qcsapi_wps_registrar_report_button_press(ifname);
	}
	else {
		EXTCFG_DEBUG("WPS is started at STA interface:%s\n", ifname);
		qcsapi_wps_enrollee_report_button_press(ifname, NULL);
	}
}

static int qtn_extcfg_return_wdev_added(struct ubus_context *ctx,
		struct ubus_request_data *req, char *ifname)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, MAP_EXTCFG_ATTR_WDEV_NAME, ifname);

	return ubus_send_reply(ctx, req, b.head);
}

static int qtn_extcfg_add_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];
	char *radio_ifname, ifname[IFNAME_MAXLEN + 1] = { 0 };

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_EXTCFG_ATTR_WIPHY]) {
		EXTCFG_ERROR("Failed to add vap: missing radio name\n");
		qtn_extcfg_return_wdev_added(ctx, req, ifname);
		return -1;
	}

	radio_ifname = (char *) blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WIPHY]);
	if (radio_ifname && !memcmp(radio_ifname, "wlan0", strlen("wlan0"))) {
		rtl_extcfg_add_wdev(tb);
		qtn_extcfg_return_wdev_added(ctx, req, ifname);
		return 0;
	}
	if (qtn_extcfg_create_wdev(tb, radio_ifname, ifname) != 0)
	{
		qtn_extcfg_return_wdev_added(ctx, req, ifname);
		return -1;
	}

	qtn_extcfg_config_wdev(tb, ifname);

	qtn_extcfg_return_wdev_added(ctx, req, ifname);

	return 0;
}

static int qtn_extcfg_del_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];
	char *ifname;

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	ifname = blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WDEV]);
	if (!ifname) {
		EXTCFG_ERROR("Failed to del vap: missing intf name\n");
		return -1;
	}

	if (!strncmp(ifname, "wlan0", strlen("wlan0")))
		rtl_extcfg_del_wdev(ifname);
	else if (!qtn_extcfg_check_intf_removable(ifname))
		qtn_extcfg_disable_unremovable_wdev(ifname);
	else
		qtn_extcfg_delete_wdev(ifname);
	return 0;
}

static int qtn_extcfg_cfg_wdev(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];
	struct blob_attr *param_tb[NUM_MAP_EXTCFG_BACKHAUL_ATTRS];
	char ifname[IFNAME_MAXLEN + 1] = { 0 };

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_EXTCFG_ATTR_WDEV]) {
		EXTCFG_ERROR("Failed to cfg vap: missing intf name\n");
		return -1;
	}

	strncpy(ifname, (char *)blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WDEV]), IFNAME_MAXLEN);
	if (!memcmp(ifname, "wlan0", strlen("wlan0")))
		rtl_extcfg_cfg_wdev(tb, ifname);
	else if (!memcmp(ifname, "wifi", strlen("wifi")))
		qtn_extcfg_config_wdev(tb, ifname);

	if (tb[MAP_EXTCFG_ATTR_BACKHAUL]) {
		blobmsg_parse(extcfg_backhaul_policy, NUM_MAP_EXTCFG_BACKHAUL_ATTRS, param_tb,
			blobmsg_data(tb[MAP_EXTCFG_ATTR_BACKHAUL]),
			blobmsg_len(tb[MAP_EXTCFG_ATTR_BACKHAUL]));
		qtn_extcfg_config_backhaul(param_tb, ifname);
	}
	return 0;
}

static int qtn_extcfg_start_wps(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];
	char *ifname, *radio_ifname;

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_EXTCFG_ATTR_WDEV]) {
		EXTCFG_ERROR("Failed to start wps: missing intf name\n");
		return -1;
	}
	radio_ifname = (char *) blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WIPHY]);
	ifname = (char *) blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WDEV]);
	if (radio_ifname && !memcmp(radio_ifname, "wlan0", strlen("wlan0")))
		system("/root/wscd -sig_pbc wlan0");
	else
		qtn_extcfg_active_wps(ifname);
	return 0;
}

static void qtn_qcsapi_get_bsscfg(char *ifname)
{
	qcsapi_SSID ssid_str = {0};
	string_16 wpa_str = {0};
	string_16 wpa_key_mgmt_str = {0};
	char  key_str[KEY_MAXLEN+1] = {0};
	qcsapi_SSID backhaul_ssid_str = {0};
	uint32_t wpa = 0;
	uint32_t auth = MAP_IEEE80211_AUTH_MODE_OPEN;  // Default use
	uint32_t encrypt = MAP_IEEE80211_ENCRYP_MODE_NONE;  // Default use
	uint32_t mtypes = 0;

	if (qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
				"ssid", ssid_str, sizeof(ssid_str)) < 0) {
		EXTCFG_ERROR("call_qcsapi get_bss_cfg %s ap %s ssid failed\n", ifname, ifname);
		return;
	}
	if (qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
				"wpa", wpa_str, sizeof(wpa_str)) < 0) {
		EXTCFG_ERROR("call_qcsapi get_bss_cfg %s ap %s wpa failed\n", ifname, ifname);
		return;
	}

	wpa = atoi(wpa_str);

	if (wpa > 0 && qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
				"wpa_key_mgmt", wpa_key_mgmt_str, sizeof(wpa_key_mgmt_str)) < 0) {
		EXTCFG_ERROR("call_qcsapi get_bss_cfg %s ap %s wpa_key_mgmt failed\n", ifname, ifname);
		return;
	}

	blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_SSID_NAME,
			(void *)ssid_str, strlen(ssid_str));

	if (wpa == 2 && !strncmp(wpa_key_mgmt_str, "WPA-EAP", sizeof("WPA-EAP")))
		auth = MAP_IEEE80211_AUTH_MODE_WPA2;
	else if ( wpa == 2 && !strncmp(wpa_key_mgmt_str, "WPA-PSK", sizeof("WPA-PSK")))
		auth = MAP_IEEE80211_AUTH_MODE_WPA2PSK;
	else if (wpa == 1 && !strncmp(wpa_key_mgmt_str, "WPA-EAP", sizeof("WPA-EAP")))
		auth = MAP_IEEE80211_AUTH_MODE_WPA;
	else if (wpa == 1 && !strncmp(wpa_key_mgmt_str, "WPA-PSK", sizeof("WPA-PSK")))
		auth = MAP_IEEE80211_AUTH_MODE_WPAPSK;
	else if (wpa == 0)
		auth = MAP_IEEE80211_AUTH_MODE_OPEN;
	else
		EXTCFG_ERROR("auth mode unsupport, wpa(%s) wpa_key_mgmt(%s)\n", wpa_str, wpa_key_mgmt_str);

	blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_AUTH_NAME, auth);

	if (wpa == 1)
		encrypt = MAP_IEEE80211_ENCRYP_MODE_TKIP;
	else if (wpa == 2)
		encrypt = MAP_IEEE80211_ENCRYP_MODE_AES;
	else if (wpa == 0)
		encrypt = MAP_IEEE80211_ENCRYP_MODE_NONE;
	else
		EXTCFG_ERROR("encrypt type unsupport, wpa(%s)\n", wpa_str);

	blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_ENCRYP_NAME, encrypt);

	if (auth & (MAP_IEEE80211_AUTH_MODE_WPA2PSK | MAP_IEEE80211_AUTH_MODE_WPAPSK)) {
		if (qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
					"wpa_passphrase", key_str, sizeof(key_str)) >= 0) {
			blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_KEY_NAME,
					(void *)key_str, strlen(key_str));
		} else if (qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
					"wpa_psk", key_str, sizeof(key_str)) >= 0) {
			blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_KEY_NAME,(void *)key_str, KEY_MAXLEN);
		} else {
			EXTCFG_ERROR("%s get key for %s failed\n", __func__, ifname);
		}
	}
	else if (auth & (MAP_IEEE80211_AUTH_MODE_WPA2 | MAP_IEEE80211_AUTH_MODE_WPA)) {
		if (qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
					"auth_server_shared_secret", key_str, sizeof(key_str)) >= 0) {
			blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAP_EXTCFG_ATTR_KEY_NAME,
					(void *)key_str, strlen(key_str));
		}
	}

	if (qcsapi_wifi_get_bss_cfg(ifname, qcsapi_access_point, ifname,
				"multiap_backhaul_bss_ssid", backhaul_ssid_str, sizeof(backhaul_ssid_str)) >= 0)
		mtypes |= MAP_INTERFACE_MTYPE_FRONTHAUL_BSS;
	/* Backhaul BSS only support WPA2-PSK mode from MAP spec*/
	if (auth == MAP_IEEE80211_AUTH_MODE_WPA2PSK &&
			qtn_extcfg_check_backhaul_bss(ifname, ssid_str, key_str))
		mtypes |= MAP_INTERFACE_MTYPE_BACKHAUL_BSS;
	blobmsg_add_u32(&b, MAP_EXTCFG_ATTR_MAP_TYPES_NAME, mtypes);

	EXTCFG_DEBUG("get original configurations of interface(%s): SSID(%s) wpa(%s) key(%s) mtypes(0x%02x)\n",
			ifname, ssid_str, wpa_str, key_str, mtypes);
}

static int qtn_extcfg_get_bsscfg(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAP_EXTCFG_ATTRS];
	char *ifname;

	blobmsg_parse(extcfg_policy, NUM_MAP_EXTCFG_ATTRS,
		tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[MAP_EXTCFG_ATTR_WDEV]) {
		EXTCFG_ERROR("Failed to get bsscfg: missing interface name\n");
		return -1;
	}
	ifname = (char *) blobmsg_get_string(tb[MAP_EXTCFG_ATTR_WDEV]);

	blob_buf_init(&b, 0);

	if (!memcmp(ifname, "wlan0", strlen("wlan0")))
		rtl_extcfg_get_bsscfg(ifname);
	else if (!memcmp(ifname, "wifi", strlen("wifi")))
		qtn_qcsapi_get_bsscfg(ifname);

	return ubus_send_reply(ctx, req, b.head);
}

#define MAP_DEVICE_DATA_CFG_MAX_LEN 100

static int qtn_extcfg_get_devdata(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)
{
	char ifname[IFNAME_MAXLEN + 1] = {0};
	qcsapi_unsigned_int max_len = MAP_DEVICE_DATA_CFG_MAX_LEN;
	char device_data_cfg[MAP_DEVICE_DATA_CFG_MAX_LEN];

	blob_buf_init(&b, 0);

	if (qcsapi_get_primary_interface(ifname, IFNAME_MAXLEN) >= 0) {

		memset(device_data_cfg, 0, MAP_DEVICE_DATA_CFG_MAX_LEN);
		if (qcsapi_wps_get_param(ifname, qcsapi_wps_device_name, device_data_cfg, max_len) == 0)
			blobmsg_add_string(&b, MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME_NAME, device_data_cfg);

		memset(device_data_cfg, 0, MAP_DEVICE_DATA_CFG_MAX_LEN);
		if (qcsapi_wps_get_param(ifname, qcsapi_wps_manufacturer, device_data_cfg, max_len) == 0)
			blobmsg_add_string(&b, MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME_NAME, device_data_cfg);

		memset(device_data_cfg, 0, MAP_DEVICE_DATA_CFG_MAX_LEN);
		if (qcsapi_wps_get_param(ifname, qcsapi_wps_model_name, device_data_cfg, max_len) == 0)
			blobmsg_add_string(&b, MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME_NAME, device_data_cfg);

		memset(device_data_cfg, 0, MAP_DEVICE_DATA_CFG_MAX_LEN);
		if (qcsapi_wps_get_param(ifname, qcsapi_wps_model_number, device_data_cfg, max_len) == 0)
			blobmsg_add_string(&b, MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER_NAME, device_data_cfg);

		memset(device_data_cfg, 0, MAP_DEVICE_DATA_CFG_MAX_LEN);
		if (qcsapi_wps_get_param(ifname, qcsapi_wps_serial_number, device_data_cfg, max_len) == 0)
			blobmsg_add_string(&b, MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER_NAME, device_data_cfg);
	}

	return ubus_send_reply(ctx, req, b.head);
}

static int qtn_extcfg_start_map_agent(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)

{
	system("/usr/sbin/start_mapagent_npu restart");
	return 0;
}

static int qtn_extcfg_start_map_controller(struct ubus_context *ctx,
	struct ubus_object *obj, struct ubus_request_data *req,
	const char *method, struct blob_attr *msg)

{
	system("/usr/sbin/start_mapcontroller_npu restart");
	return 0;
}

static const struct ubus_method qtn_extcfg_methods[] = {
	UBUS_METHOD(MAP_EXTCFG_METHOD_CFG_WIPHY, qtn_extcfg_cfg_wiphy, extcfg_wiphy_policy),
	UBUS_METHOD(MAP_EXTCFG_METHOD_ADD_WDEV, qtn_extcfg_add_wdev, extcfg_policy),
	UBUS_METHOD(MAP_EXTCFG_METHOD_DEL_WDEV, qtn_extcfg_del_wdev, extcfg_policy),
	UBUS_METHOD(MAP_EXTCFG_METHOD_CFG_WDEV, qtn_extcfg_cfg_wdev, extcfg_policy),
	UBUS_METHOD(MAP_EXTCFG_METHOD_START_WPS, qtn_extcfg_start_wps, extcfg_policy),
	UBUS_METHOD(MAP_EXTCFG_METHOD_GET_BSSCFG, qtn_extcfg_get_bsscfg, extcfg_policy),
	UBUS_METHOD_NOARG(MAP_EXTCFG_METHOD_GET_DEVDATA, qtn_extcfg_get_devdata),
	UBUS_METHOD_NOARG(MAP_EXTCFG_METHOD_START_MAP_AGENT, qtn_extcfg_start_map_agent),
	UBUS_METHOD_NOARG(MAP_EXTCFG_METHOD_START_MAP_CONTROLLER, qtn_extcfg_start_map_controller),
};

static struct ubus_object_type qtn_extcfg_obj_type =
	UBUS_OBJECT_TYPE(MAP_EXTCFG_OBJ_NAME, qtn_extcfg_methods);

static struct ubus_object qtn_extcfg_obj = {
	.name = MAP_EXTCFG_OBJ_NAME,
	.type = &qtn_extcfg_obj_type,
	.methods = qtn_extcfg_methods,
	.n_methods = ARRAY_SIZE(qtn_extcfg_methods),
};

int main(int argc, char *argv[])
{
	int ret;

	uloop_init();

	if (!(g_ubus_ctx = ubus_connect(NULL))) {
		EXTCFG_ERROR("Failed to connect ubus\n");
		return -1;
	}

	ubus_add_uloop(g_ubus_ctx);

	ret = ubus_add_object(g_ubus_ctx, &qtn_extcfg_obj);
	if (ret) {
		EXTCFG_ERROR("Failed to add ubus %s object: %s\n",
			qtn_extcfg_obj.name, ubus_strerror(ret));
		return -1;
	}

#ifdef QTN_REMOTE_RPC_CALL
	EXTCFG_DEBUG("map_extcfg create remote rpc entity\n");
#ifdef Q_OPENWRT
	if (qtn_rpc_connect(argv[1]) != 0)
		EXTCFG_ERROR("remote rpc entity is failed to create!\n");
#else
	if (qtn_rpc_connect() != 0)
		EXTCFG_ERROR("remote rpc entity is failed to create!\n");
#endif
#endif

	blob_buf_init(&b, 0);
	EXTCFG_DEBUG("map_extcfg is running\n");

#ifdef Q_OPENWRT
	// unit test for qwe rpc call
	if (argc > 2 && !strcmp(argv[2], "-t"))
	{
		char param[32] = {0};
		char value[64] = {0};
		int len_value = 0;
		char qwecfg_output[QWECFG_OUTPUT_MAX] = {0};

		sprintf(param, "fragthres.wlan1");
		EXTCFG_DEBUG("Test #1: rtl_qwecfg_get %s\n", param);
		if (!rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG))
			EXTCFG_DEBUG("Test #1: Pass - rtl_qwecfg_get %s = %d\n", param, atoi(value));
		else
			EXTCFG_DEBUG("Test #1: Fail - rtl_qwecfg_get %s\n", param);

		sprintf(param, "ssid.wlan1");
		EXTCFG_DEBUG("Test #2: rtl_qwecfg_get %s\n", param);
		if (!rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG))
			EXTCFG_DEBUG("Test #2: Pass - rtl_qwecfg_get success %s = %s\n", param, value);
		else
			EXTCFG_DEBUG("Test #2: Fail - rtl_qwecfg_get fail %s\n", param);

		sprintf(param, "passphrase.wlan1");
		EXTCFG_DEBUG("Test #3: rtl_qwecfg_get %s\n", param);
		if (!rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_STRING, CFGMETHOD_TYPE_QWECFG))
			EXTCFG_DEBUG("Test #3: Pass - rtl_qwecfg_get %s = %s\n", param, value);
		else
			EXTCFG_DEBUG("Test #3: Fail - rtl_qwecfg_get %s\n", param);

		sprintf(param, "vlanid.wlan1");
		EXTCFG_DEBUG("Test #4: rtl_qwecfg_get %s\n", param);
		if (!rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG))
			EXTCFG_DEBUG("Test #4: Pass - rtl_qwecfg_get success %s = %d\n", param, atoi(value));
		else
			EXTCFG_DEBUG("Test #4: Fail - rtl_qwecfg_get %s\n", param);

		EXTCFG_DEBUG("Test #5: rtl_qwecfg_set %s = %d\n", param, 999);
		if (rtl_qwecfg_set(param, NULL, 999, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG) == 1)
			EXTCFG_DEBUG("Test #5: Pass - rtl_qwecfg_set success %s\n", param);
		else
			EXTCFG_ERROR("Test #5: Fail - rtl_qwecfg_set %s\n", param);

		EXTCFG_DEBUG("Test #6: rtl_qwecfg_get %s\n", param);
		if (!rtl_qwecfg_get(param, strlen(param), value, &len_value, PARAM_TYPE_INT, CFGMETHOD_TYPE_QWECFG))
			EXTCFG_DEBUG("Test #6: Pass - rtl_qwecfg_get success %s = %d\n", param, atoi(value));
		else
			EXTCFG_DEBUG("Test #6: Fail - rtl_qwecfg_get %s\n", param);

		EXTCFG_DEBUG("Test #7: qweconfig default\n");
		if (!qcsapi_qwe_command("qweconfig", "default", NULL, NULL, qwecfg_output, QWECFG_OUTPUT_MAX))
			EXTCFG_DEBUG("Test #7: Pass - qweconfig default\n");
		else
			EXTCFG_DEBUG("Test #7: Fail - qweconfig default\n");

		EXTCFG_DEBUG("Test #8: qweaction wlan1 commit\n");
		if (!qcsapi_qwe_command("qweaction", "wlan1", "commit", NULL, qwecfg_output, QWECFG_OUTPUT_MAX))
			EXTCFG_DEBUG("Test #8: Pass - qweaction wlan1 commit\n");
		else
			EXTCFG_DEBUG("Test #8: Fail - qweaction wlan1 commit\n");

		return 0;
	}
#endif

	uloop_run();

	blob_buf_free(&b);
	uloop_done();
	ubus_free(g_ubus_ctx);

#ifdef QTN_REMOTE_RPC_CALL
	EXTCFG_DEBUG("map_extcfg destroy remote rpc entity\n");
	qtn_rpc_disconnect();
#endif

	return 0;
}
