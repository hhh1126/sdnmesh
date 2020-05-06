/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _CSM_TEST_H_
#define _CSM_TEST_H_

extern int csm_mbo_reg_frm_cmd(void *ctx, uint8_t *bss_mac, uint8_t txrx, uint8_t subtype,
	uint8_t drv_process, uint8_t match_len, uint8_t *match);
extern int csm_mbo_send_frame_cmd(void *ctx, uint8_t *bssid, uint8_t channel,
	uint16_t frm_len, uint8_t *frm);

#endif
