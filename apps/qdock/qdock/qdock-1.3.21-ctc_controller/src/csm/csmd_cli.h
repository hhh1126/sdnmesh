/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSMD_CLI_H_
#define _CSMD_CLI_H_

#define MAX_CTRL_MSG_LEN	1024
/* for MORE byte */
#define RESERVE_LEN		1
#define CTRL_MSG_MORE		1
#define CTRL_MSG_END		0

#define MAX_VALID_CTRL_MSG_LEN	(MAX_CTRL_MSG_LEN - RESERVE_LEN)
#define VALID_CTRL_MSG_HEAD(_buf)	((_buf) + RESERVE_LEN)
#define VALID_CTRL_MSG_LEN(_len)	((_len) - RESERVE_LEN)

#define CSMD_CLI_UN_PATH	"/tmp/.QTNCSMD_CLI_AF_UNIX"

#endif
