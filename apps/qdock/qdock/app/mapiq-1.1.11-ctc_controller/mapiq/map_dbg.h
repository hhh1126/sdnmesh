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

#ifndef __MAP_DBG_H__
#define __MAP_DBG_H__

#define MAP_ERROR(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_ERR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define MAP_WARN(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_WARNING, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define MAP_NOTICE(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_NOTICE, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define MAP_INFO(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define MAP_DEBUG(fmt,...)	csm_log_printf(g_ctx.log_handle, LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define MAP_DUMP(_t, _d, _s)	csm_log_dump(g_ctx.log_handle, _t, __func__, __LINE__, (uint8_t *)(_d), _s)
#define MAP_LOG_INIT(_level)	do {g_ctx.log_handle = csm_log_register(COLORFUL_STR(COLOR_BLUE, "MAP "), _level); } while(0)

static inline int map_set_log_level(const char *name)
{
	return csm_log_set_level_by_handle(g_ctx.log_handle, name);
}
#endif
