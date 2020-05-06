/*
 *  Copyright (c) 2019, Semiconductor Components Industries, LLC
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

/** @file
 * @brief defines and interfaces for al_map_server
 *
 * This file provide defines and interfaces for al_map_server
 */

#ifndef AL_UBUS_SERVER_H
#define AL_UBUS_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/ether.h>

#include <libubox/uloop.h>
#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "hlist.h"
#include "qdock_map_api.h"

#ifdef MAPIQ_DEVID_STRING_FORMAT
#define MAPAPI_DEVID_LEN    18      /* xx:xx:xx:xx:xx:xx */
#define BLOBMSG_TYPE_MAC BLOBMSG_TYPE_STRING
#else
#define MAPAPI_DEVID_LEN    6
#define BLOBMSG_TYPE_MAC BLOBMSG_TYPE_UNSPEC
#endif

enum
{
    MAPAPI_RESULT_SUCCESS = 0,
    MAPAPI_RESULT_INVALID_VALUE,
    MAPAPI_RESULT_INVALID_ARGUMENT,
    MAPAPI_RESULT_INVALID_EXECUTION,
    MAPAPI_RESULT_MISS_ARGUMENT,
    MAPAPI_RESULT_CONTEXT_NOT_FOUND,
    MAPAPI_RESULT_NOT_SUPPORTED,
    MAPAPI_RESULT_UNKNOWN_ERROR,
};

enum {
    MAPAPI_GET_MAP_ATTR_DEVICES = 0,
    MAPAPI_GET_MAP_ATTR_AL_ID,
    MAPAPI_GET_MAP_ATTR_RADIOS,
    MAPAPI_GET_MAP_ATTR_RADIO_ID,
    MAPAPI_GET_MAP_ATTR_BSSES,
    MAPAPI_GET_MAP_ATTR_BSS_ID,
    MAPAPI_GET_MAP_ATTR_STATIONS,
    MAPAPI_GET_MAP_ATTR_STA_MAC,
    MAPAPI_GET_MAP_ATTR_FMT_CTL,

    NUM_MAPAPI_GET_MAP_ATTRS,
};

enum {
    MAPAPI_PARAM_ATTR_MAC = 0,
    NUM_MAPAPI_PARAM_MAC_ATTRS,
};

extern struct blob_buf b;
extern const struct blobmsg_policy mapapi_set_policy[NUM_MAPAPI_SET_ATTRS];
extern const struct blobmsg_policy mapapi_get_map_policy[NUM_MAPAPI_GET_MAP_ATTRS];
extern struct blobmsg_policy mapapi_param_mac_policy[NUM_MAPAPI_PARAM_MAC_ATTRS];


// Declares of get ubus mapapi objects
struct ubus_object *get_mapapi_obj(void);
struct ubus_object *get_mapapi_controller_obj(void);
struct ubus_object *get_mapapi_local_obj(void);
struct ubus_object *get_mapapi_network_obj(void);
struct ubus_object *get_mapapi_config_obj(void);

// Common functions shared by all ubus interfaces
int string_to_binary(const char *bin_str, uint8_t **bins, uint32_t *len);
void blobmsg_add_mac(struct blob_buf *buf, const char *name, uint8_t *mac);
void blobmsg_get_mac(struct blob_attr *attr, uint8_t *mac);
void blobmsg_add_binary(struct blob_buf *buf, const char *name, uint8_t *data, uint32_t len);
void fill_result(uint8_t rc);
void array_mac_to_dlist(void *ctx, void *param, void *data, int len);
void visit_attrs(struct blob_attr *attrs, void (*cb)(void *, void *, void *, int), void *ctx, void *param);

// Functions used by platform
int mapapi_server_init(void);
void mapapi_server_deinit(void);
int mapapi_config_init(void);
void mapapi_config_deinit(void);

// Function used by mapapi_config
void free_list_mapapi_config_obj(void);

#endif
