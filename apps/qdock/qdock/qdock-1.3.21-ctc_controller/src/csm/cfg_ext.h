/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.          **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/

#ifndef __QSTEER_CFG_API_H__
#define __QSTEER_CFG_API_H__

/**
 * \brief Ask whether master mode is allowed.
 *
 *  Q-Comm-M will call this function to ask whether this platform is allowed to be master.
 *
 * \\return 1 if allowed and 0 if not allowed.
 */
int qsteer_master_mode_allowed(void);

/**
 * \brief Get the current AP configuration of the device.
 *
 * Q-Comm-M will call this function to ask platform to save current AP configuration to a file
 *
 * \param path pointer to the path of the file contains the current AP configuration
 *
 * \\return 0 on success and other for failure
 */
int qsteer_get_cfg(const char *path);

/**
 * \brief Set the AP configuration to the device.
 *
 * Q-Comm-M will call this function to ask platform to apply new AP configuration
 *
 * \param path pointer to the path of the file contains the new AP configuration
 *
 * \\return 0 on success and other for failure
 */
int qsteer_set_cfg(const char *path);

/**
 * \brief Report the feedback of qsteer_cfg_update().
 *
 * Q-Comm-M will call this function to report the feedback of qsteer_cfg_update to platform.
 *
 * \param path pointer to the path of the file contains the feedback
 */
void qsteer_report_update_feedback(const char *path);

/**
 * \brief Apply local config
 *
 * Q-Comm-M will call this function to ask platform to apply local AP configuration
 *
 * \\return 0 on success and other for failure
 */
int qsteer_apply_local_cfg(void);

#endif

