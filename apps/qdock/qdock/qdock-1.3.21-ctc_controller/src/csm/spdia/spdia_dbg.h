/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          		 **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef __SPDIA_DBG_H__
#define __SPDIA_DBG_H__

#if 0

#define SPDIA_ERROR(fmt, ...)
#define SPDIA_WARN(fmt, ...)
#define SPDIA_NOTICE(fmt, ...)
#define SPDIA_INFO(fmt, ...)
#define SPDIA_DEBUG(fmt,...)
#define SPDIA_DUMP(_t, _d, _s)
#define SPDIA_LOG_INIT(_level)
#define SPDIA_SET_LOG_LEVEL(_name)

#else

#define SPDIA_ERROR(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_ERR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define SPDIA_WARN(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_WARNING, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define SPDIA_NOTICE(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_NOTICE, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define SPDIA_INFO(fmt, ...)	csm_log_printf(g_ctx.log_handle, LOG_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define SPDIA_DEBUG(fmt,...)	csm_log_printf(g_ctx.log_handle, LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define SPDIA_DUMP(_t, _d, _s)	csm_log_dump(g_ctx.log_handle, _t, __func__, __LINE__, (uint8_t *)(_d), _s)
#define SPDIA_LOG_INIT(_level)	do {g_ctx.log_handle = csm_log_register(COLORFUL_STR(COLOR_BLUE, "QSPD"), _level); } while(0)
#define SPDIA_SET_LOG_LEVEL(_name)	csm_log_set_level_by_handle(g_ctx.log_handle, _name)

#endif

#endif

