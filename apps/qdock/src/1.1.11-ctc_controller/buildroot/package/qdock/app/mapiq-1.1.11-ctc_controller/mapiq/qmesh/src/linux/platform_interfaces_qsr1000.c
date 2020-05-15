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

/** @file
 * @brief Driver interface for QSR1000/QSR10K
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <platform.h>

int qsr1000_init_push_button(void)
{
    struct sockaddr_nl addr;
    int sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sk < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Failed to open socket for qsr1000 push button event: %s",
            strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;

    if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Failed to bind socket for qsr1000 push button event: %s",
            strerror(errno));
        close(sk);
        return -1;
    }

    return sk;
}

void qsr1000_deinit_push_button(int sk)
{
    if (sk >= 0)
        close(sk);
}

static int qsr1000_pbc_pressed = 0;
void qsr1000_process_wireless_event_wireless_custom(char *custom)
{
    if (strncmp(custom, "WPS-BUTTON.indication", 21) == 0)
        qsr1000_pbc_pressed = 1;
}

static void qsr1000_process_wireless_event(char *data, int len)
{
    struct iw_event iwe_buf, *iwe = &iwe_buf;
    char *pos, *end, *custom;

    pos = data;
    end = data + len;

    while (pos + IW_EV_LCP_LEN <= end)
    {
        memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);

        if (iwe->len <= IW_EV_LCP_LEN)
            return;

        custom = pos + IW_EV_POINT_LEN;

        if ((iwe->cmd == IWEVCUSTOM))
        {
            char *dpos = (char *) &iwe_buf.u.data.length;
            int dlen = dpos - (char *) &iwe_buf;
            memcpy(dpos, pos + IW_EV_LCP_LEN, sizeof(struct iw_event) - dlen);
        }
        else
        {
            memcpy(&iwe_buf, pos, sizeof(struct iw_event));
            custom += IW_EV_POINT_OFF;
        }
        switch (iwe->cmd) {
        case IWEVCUSTOM:
            if (custom + iwe->u.data.length > end)
                return;
            qsr1000_process_wireless_event_wireless_custom(custom);
            break;
        default:
            break;
        }
        pos += iwe->len;
    }
}

static uint8_t qsr1000_buf[8012];
int qsr1000_check_button_pressed(int sk)
{
    int len;
    struct nlmsghdr *h;

    qsr1000_pbc_pressed = 0;

    if (sk < 0)
        return 0;

    len = recvfrom(sk, qsr1000_buf, sizeof(qsr1000_buf),
        MSG_DONTWAIT, NULL, NULL);
    if (len < 0)
    {
        if (errno != EINTR && errno != EAGAIN)
            PLATFORM_PRINTF_DEBUG_ERROR("Failed receive from qsr1000 push button event\n");
        return 0;
    }

    h = (struct nlmsghdr *)qsr1000_buf;
    while (NLMSG_OK(h, len))
    {
        switch (h->nlmsg_type)
        {
            case RTM_NEWLINK:
            {
                int attrlen, rta_len;
                struct rtattr *attr;
                if (NLMSG_PAYLOAD(h, 0) < sizeof(struct ifinfomsg))
                    return 0;
                attrlen = NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg));
                attr = (struct rtattr *)(NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
                rta_len = RTA_ALIGN(sizeof(struct rtattr));

                while (RTA_OK(attr, attrlen))
                {
                    switch (attr->rta_type)
                    {
                        case IFLA_WIRELESS:
                            qsr1000_process_wireless_event(((char *) attr) + rta_len,
                                attr->rta_len -	rta_len);
                             break;
                    }
                    attr = RTA_NEXT(attr, attrlen);
                }

                break;
            }
            default:
                break;
        }

        h = NLMSG_NEXT(h, len);
    }

    if (len > 0)
        PLATFORM_PRINTF_DEBUG_WARNING("Extra %u bytes in the end of netlink message", len);

    return qsr1000_pbc_pressed;
}
