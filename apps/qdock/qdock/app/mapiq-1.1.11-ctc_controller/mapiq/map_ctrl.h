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

#ifndef __MAP_CTRL_H__
#define __MAP_CTRL_H__

#define MAP_CTRL_OBJ_NAME		"qdock.hal"

#define MAP_CTRL_METHOD_HELP_NAME		"help"
#define MAP_CTRL_METHOD_GET_VERSION_NAME	"get_version"
#define MAP_CTRL_METHOD_SET_CONFIG_NAME		"set_config"
#define MAP_CTRL_METHOD_GET_CONFIG_NAME		"get_config"
#define MAP_CTRL_METHOD_TEST_NAME		"test"

#define MAP_CTRL_ATTR_RC_NAME			"rc"
#define MAP_CTRL_ATTR_FORMAT_NAME		"format"
#define MAP_CTRL_ATTR_METHODS_NAME		"method"
#define MAP_CTRL_ATTR_VERSION_NAME		"version"
#define MAP_CTRL_ATTR_CONFIGS_NAME		"configs"
#define MAP_CTRL_ATTR_TEST_SUBCMD_NAME		"test_subcmd"
#define MAP_CTRL_ATTR_TEST_PARAMS_NAME		"test_params"
enum map_ctrl_attrs {
	MAP_CTRL_ATTR_RC = 0,
	MAP_CTRL_ATTR_FORMAT,
	MAP_CTRL_ATTR_METHODS,
	MAP_CTRL_ATTR_VERSION,
	MAP_CTRL_ATTR_CONFIGS,
	MAP_CTRL_ATTR_TEST_SUBCMD,
	MAP_CTRL_ATTR_TEST_PARAMS,

	/* keep last */
	NUM_MAP_CTRL_ATTRS,
	MAX_MAP_CTRL_ATTR = NUM_MAP_CTRL_ATTRS - 1
};

enum {
	MAP_CTRL_RC_OK = 0,
	MAP_CTRL_RC_INVALID_VALUE,
	MAP_CTRL_RC_MISS_ARGUMENT,
	MAP_CTRL_RC_NOT_SUPPORTED,
	MAP_CTRL_RC_UNKNOWN_ERROR,
};

#define MAP_CTRL_CONF_ATTR_XXX_NAME			"xxx"
enum map_ctrl_conf_attrs {
	MAP_CTRL_CONF_ATTR_XXX = 0,

	/* keep last */
	NUM_MAP_CTRL_CONF_ATTRS,
	MAX_MAP_CTRL_CONF_ATTR = NUM_MAP_CTRL_CONF_ATTRS - 1
};

#define MAP_CTRL_TESTPARAM_ATTR_WDEV_ID_NAME		"wdev_id"
#define MAP_CTRL_TESTPARAM_ATTR_FRONTHAUL_BSS_NAME	"fbss"
#define MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_BSS_NAME	"bbss"
#define MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_STA_NAME	"bsta"
enum map_ctrl_testparam_attrs {
	MAP_CTRL_TESTPARAM_ATTR_WDEV_ID = 0,
	MAP_CTRL_TESTPARAM_ATTR_FRONTHAUL_BSS,
	MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_BSS,
	MAP_CTRL_TESTPARAM_ATTR_BACKHAUL_STA,

	/* keep last */
	NUM_MAP_CTRL_TESTPARAM_ATTRS,
	MAX_MAP_CTRL_TESTPARAM_ATTR = NUM_MAP_CTRL_TESTPARAM_ATTRS - 1
};

typedef struct map_ctrl_conf {
	int min;
	int max;
	int (*valid)(struct blob_attr *);
} map_ctrl_conf_t;

typedef struct map_ctrl_test {
	const char *subcmd;
	uint32_t (*process_subcmd_cb)(struct blob_attr **);
} map_ctrl_test_t;

extern void map_config_bss_mtype(char *ssid, uint8_t mtype);
extern void map_del_intf_config(char *ssid);
extern void map_load_intf_config(const char *in_str,
	int is_fh, int is_bh);
extern void map_del_all_intf_config();
extern void map_init_wdev(uint8_t *dev_mac);
extern int map_ctrl_init(void);
extern void map_ctrl_deinit(void);

#endif
