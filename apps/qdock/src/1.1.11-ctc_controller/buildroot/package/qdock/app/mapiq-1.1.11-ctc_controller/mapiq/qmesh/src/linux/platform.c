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
 *
 *  Portions of this software may include:
 *  Broadband Forum IEEE 1905.1/1a stack
 *  Copyright (c) 2017, Broadband Forum
 *  prplMesh Wi-Fi Multi-AP
 *  Copyright (c) 2018, prpl Foundation
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

#include <platform.h>
#include <platform_linux.h>

#include <stdlib.h>      // free(), malloc(), ...
#include <string.h>      // memcpy(), memcmp(), ...
#include <stdio.h>       // printf(), ...
#include <stdarg.h>      // va_list
#include <sys/time.h>    // gettimeofday()
#include <sys/stat.h>
#include <errno.h>       // errno

#include <arpa/inet.h>        // htons()
#include <linux/if_packet.h>  // sockaddr_ll
#include <net/if.h>           // struct ifreq, IFNAZSIZE
#include <netinet/ether.h>    // ETH_P_ALL, ETH_A_LEN
#include <sys/socket.h>       // socket()
#include <sys/ioctl.h>        // ioctl(), SIOCGIFINDEX
#include <unistd.h>           // close()

#ifndef _FLAVOUR_X86_WINDOWS_MINGW_
#    include <pthread.h> // mutexes, pthread_self()
#endif



////////////////////////////////////////////////////////////////////////////////
// Private functions, structures and macros
////////////////////////////////////////////////////////////////////////////////

// *********** libc stuff ******************************************************

// We will use this variable to save the instant when "PLATFORM_INIT()" was
// called. This way we sill be able to get relative timestamps later when
// someone calls "PLATFORM_GET_TIMESTAMP()"
//
static struct timeval tv_begin;

// The following variable is used to set which "PLATFORM_PRINTF_DEBUG_*()"
// functions should be ignored:
//
//   0 => Only print ERROR messages
//   1 => Print ERROR and WARNING messages
//   2 => Print ERROR, WARNING and INFO messages
//   3 => Print ERROR, WARNING, INFO and DETAIL messages
//
static int verbosity_level = 2;

// Mutex to avoid STDOUT "overlaping" due to different threads writing at the
// same time.
//
#ifndef _FLAVOUR_X86_WINDOWS_MINGW_
pthread_mutex_t printf_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif


////////////////////////////////////////////////////////////////////////////////
// Platform API: libc stuff
////////////////////////////////////////////////////////////////////////////////


void PLATFORM_PRINTF(const char *format, ...)
{
    va_list arglist;

#ifndef _FLAVOUR_X86_WINDOWS_MINGW_
    pthread_mutex_lock(&printf_mutex);
#endif

    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );

#ifndef _FLAVOUR_X86_WINDOWS_MINGW_
    pthread_mutex_unlock(&printf_mutex);
#endif

    return;
}


#define PLATFORM_PRINTF_FUNC_DEFINE(name, value) \
void platform_printf_debug_##name(const char *func, uint32_t line, const char *format, ...)\
{\
    va_list arglist;\
    uint32_t ts;\
    ts = PLATFORM_GET_TIMESTAMP();\
    if (verbosity_level < (value))\
        return; \
    printf("[%03d.%03d](%-20.20s:%04u)", ts/1000, ts%1000, func, line); \
    printf("%-8.8s:", ""#name""); \
    va_start( arglist, format ); \
    vprintf( format, arglist ); \
    va_end( arglist ); \
}

#define PLATFORM_PRINTF_RAW_FUNC_DEFINE(name, value) \
void PLATFORM_PRINTF_RAW_##name(const char *format, ...)\
{\
    va_list arglist;\
    uint32_t ts;\
    ts = PLATFORM_GET_TIMESTAMP();\
    if (verbosity_level < (value))\
        return; \
    printf("[%03d.%03d](%-20.20s:%04u)", ts/1000, ts%1000, __FUNCTION__, __LINE__); \
    printf("RAW     : "); \
    va_start( arglist, format ); \
    vprintf( format, arglist ); \
    va_end( arglist ); \
}

PLATFORM_PRINTF_RAW_FUNC_DEFINE(ERROR, 0)
PLATFORM_PRINTF_RAW_FUNC_DEFINE(WARNING, 1)
PLATFORM_PRINTF_RAW_FUNC_DEFINE(INFO, 2)
PLATFORM_PRINTF_RAW_FUNC_DEFINE(DETAIL,3)
PLATFORM_PRINTF_RAW_FUNC_DEFINE(VERBOSE, 4)

PLATFORM_PRINTF_FUNC_DEFINE(error, 0)
PLATFORM_PRINTF_FUNC_DEFINE(warning, 1)
PLATFORM_PRINTF_FUNC_DEFINE(info, 2)
PLATFORM_PRINTF_FUNC_DEFINE(detail, 3)
PLATFORM_PRINTF_FUNC_DEFINE(verbose, 4)



void PLATFORM_PRINTF_DEBUG_SET_VERBOSITY_LEVEL(int level)
{
    verbosity_level = level;
}

uint32_t PLATFORM_GET_TIMESTAMP(void)
{
    struct timeval tv_end;
    uint32_t diff;

    gettimeofday(&tv_end, NULL);

    diff = (tv_end.tv_usec - tv_begin.tv_usec) / 1000 + (tv_end.tv_sec - tv_begin.tv_sec) * 1000;

    return diff;
}

static uint8_t dump_mask = 0;
static uint32_t dump_kbytes = 500;
static FILE *dump_rx_file = NULL, *dump_tx_file = NULL;
static int dump_rx_ind = 0, dump_tx_ind = 0;
pthread_mutex_t dump_rx_mutex, dump_tx_mutex;
#define DUMP_RX_PACKET_FNAME    "/tmp/map_rx_packets"
#define DUMP_TX_PACKET_FNAME    "/tmp/map_tx_packets"
static FILE *dump_packet_file_open(uint32_t type)
{
    char cname[32];
    struct stat stat;
    bool is_rx = (type == DUMP_RX_PACKETS) ? true : false;
    int *ind = is_rx ? &dump_rx_ind : &dump_tx_ind;
    FILE **file = is_rx ? &dump_rx_file : &dump_tx_file;
    const char *fname;

    if (!*file)
        *ind = 1;
    else if (0 == fstat(fileno(*file), &stat)
        && stat.st_size > (dump_kbytes << 10))
        fclose(*file);
    else
        return *file;

    *ind += 1;
    fname = is_rx ? DUMP_RX_PACKET_FNAME : DUMP_TX_PACKET_FNAME;
    snprintf(cname, 32, "%s%u", fname, (*ind) & 0x01);
	*file = fopen(cname, "w");
    return *file;
}

static void dump_packet_init(void)
{
    pthread_mutex_init(&dump_rx_mutex, NULL);
    pthread_mutex_init(&dump_tx_mutex, NULL);
}

void PLATFORM_SET_DUMP_PACKETS(uint8_t mask, uint32_t kbytes)
{
    dump_mask = mask;
    dump_kbytes = kbytes;
}

void PLATFORM_DUMP_PACKETS_INTO_FILE(uint32_t type, const char *ifname, uint8_t *packet, uint32_t len)
{
    uint32_t i;
    char *buf, *pos;
    FILE *file;
    pthread_mutex_t *mutex;

    if (!(dump_mask & type) || !dump_kbytes)
        return;

    pos = buf = malloc(strlen(ifname) + 2 + len * 3 + (len >> 4) + 10 + 3 + 1 + 1);
    pos += sprintf(pos, "#%s\n", ifname);
    pos += sprintf(pos, "[%08u:", PLATFORM_GET_TIMESTAMP());
    for (i = 0; i < len; i++) {
        if ((i & 0x0f) == 0)
            pos += sprintf(pos, "\n");
        pos += sprintf(pos, "%02x ", packet[i]);
    }
    pos += sprintf(pos, "\n]\n");

    mutex = (type == DUMP_RX_PACKETS) ? &dump_rx_mutex : &dump_tx_mutex;
    pthread_mutex_lock(mutex);
    file = dump_packet_file_open(type);
    if (file)
    {
        fprintf(file, "%s", buf);
        fflush(file);
    }
    pthread_mutex_unlock(mutex);

    free(buf);
}

////////////////////////////////////////////////////////////////////////////////
// Platform API: Initialization functions
////////////////////////////////////////////////////////////////////////////////

struct ubus_context *platform_ubus = NULL;
uint8_t PLATFORM_INIT(void)
{

    // Call "_timeval_print()" for the first time so that the initialization
    // time is saved for future reference.
    //
    gettimeofday(&tv_begin, NULL);

    uloop_init();
    if (!(platform_ubus = ubus_connect(NULL))) {
        PLATFORM_PRINTF_DEBUG_ERROR("create ubus context failed\n");
        return 0;
    }

    ubus_add_uloop(platform_ubus);

    dump_packet_init();

    return 1;
}

int getIfIndex(const char *interface_name)
{
    int                 s;
    struct ifreq        ifr;

#ifdef Q_OPENWRT
    PLATFORM_PRINTF_DEBUG_DETAIL("%s socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)\n", __func__);
#endif
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1 == s)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] socket('%s') returned with errno=%d (%s) while opening a RAW socket\n",
                                    interface_name, errno, strerror(errno));
        return -1;
    }

#ifdef Q_OPENWRT
    PLATFORM_PRINTF_DEBUG_DETAIL("%s interface_name: %s\n", __func__, interface_name);
#endif
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) == -1)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] %s ioctl('%s',SIOCGIFINDEX) returned with errno=%d (%s) while opening a RAW socket\n",
                                    __func__, ifr.ifr_name, errno, strerror(errno));
        close(s);
        return -1;
    }

    close(s);
#ifdef Q_OPENWRT
    PLATFORM_PRINTF_DEBUG_DETAIL("%s ifindex: %d\n", __func__, ifr.ifr_ifindex);
#endif
    return ifr.ifr_ifindex;
}

int openPacketSocket(int ifindex, uint16_t eth_type)
{
    int                 s;
    struct sockaddr_ll  socket_address;

    s = socket(AF_PACKET, SOCK_RAW, htons(eth_type));
    if (-1 == s)
    {
        return -1;
    }

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family   = AF_PACKET;
    socket_address.sll_ifindex  = ifindex;
    socket_address.sll_protocol = htons(eth_type);

    if (-1 == bind(s, (struct sockaddr*)&socket_address, sizeof(socket_address)))
    {
        close(s);
        return -1;
    }

    return s;
}

static void platform_timer_to(struct uloop_timeout *to)
{
    struct platform_timer *timer = (struct platform_timer *)
        container_of(to, struct platform_timer, to);

    PLATFORM_PRINTF_DEBUG_DETAIL("Process the timer %p\n", timer);

    if (timer->cb)
        timer->cb(timer->ctx, timer->param);

    free(timer);
}

void *PLATFORM_SET_TIMEOUT(uint32_t ms,
    void (*cb)(void *, void *), void *ctx, void *param)
{
    struct platform_timer *timer = malloc(sizeof(*timer));
    if (!timer)
        return NULL;
    memset(timer, 0, sizeof(*timer));
    timer->to.cb = platform_timer_to;
    timer->ms = ms;
    timer->ctx = ctx;
    timer->param = param;
    timer->cb = cb;

    if (uloop_timeout_set(&timer->to, ms) < 0)
    {
        free(timer);
        return NULL;
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("Fire the timer %p, timeout is %ums\n", timer, ms);

    return timer;
}

int PLATFORM_CANCEL_TIMEOUT(void *id)
{
    struct platform_timer *timer = (struct platform_timer *)id;
    if (!timer)
        return -1;

    PLATFORM_PRINTF_DEBUG_DETAIL("Cancel the timer %p\n", timer);

    if (uloop_timeout_cancel(&timer->to) < 0)
        return -1;

    free(timer);
    return 0;
}
