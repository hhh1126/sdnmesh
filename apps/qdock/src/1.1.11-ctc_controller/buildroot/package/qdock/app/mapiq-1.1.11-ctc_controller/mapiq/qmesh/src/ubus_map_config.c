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
 * @brief ubus map config object implementation
 *
 */
#include "qdock_map_api.h"
#include "al_ubus_server.h"

#include "platform.h"
#include "datamodel.h"
#include "al_utils.h"
#include "al_send.h"
#include "al.h"


extern const char *result_strings[];

#define MAPAPI_CONFIG_BLOBMSG_ADD_CONF(_t, _c, _s) blobmsg_add_##_t(&b, #_c, _s._c)


static const struct ubus_method mapapi_config_methods[] = {
	};
static struct ubus_object_type mapapi_config_obj_type =
	UBUS_OBJECT_TYPE(MAPAPI_CONFIG_OBJ_NAME, mapapi_config_methods);

static struct ubus_object mapapi_config_obj = {
	.name = MAPAPI_CONFIG_OBJ_NAME,
	.type = &mapapi_config_obj_type,
	.methods = mapapi_config_methods,
	.n_methods = ARRAY_SIZE(mapapi_config_methods),
};

void free_list_mapapi_config_obj()
{
}

struct ubus_object *get_mapapi_config_obj(void)
{
	return &mapapi_config_obj;
}
