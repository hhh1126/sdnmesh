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

#include <datamodel.h>
#include <platform.h>
#include "../platform_os.h"
#include "../al_datamodel.h"
#include "platform_os_priv.h"
#include "platform_alme_server_priv.h"
#include <platform_linux.h>
#ifdef QDOCK
#include <sys/un.h>
#include <libubox/usock.h>
#include "platform_qdock.h"
#endif
#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
#include "platform_interfaces_qsr1000_priv.h"
#endif
#include "platform_interfaces_priv.h"            // addInterface
#include <utils.h>
#include <1905_l2.h>

#include <stdlib.h>      // free(), malloc(), ...
#include <stdio.h>       // fopen(), FILE, sprintf(), fwrite()
#include <string.h>      // memcpy(), memcmp(), ...
#include <pthread.h>     // threads and mutex functions
#include <mqueue.h>      // mq_*() functions
#include <errno.h>       // errno
#include <poll.h>        // poll()
#include <sys/inotify.h> // inotify_*()
#include <unistd.h>      // read(), sleep()
#include <signal.h>      // struct sigevent, SIGEV_*
#include <netinet/ether.h>    // ETH_P_ALL, ETH_A_LEN
#include <sys/types.h>   // recv(), setsockopt()
#include <sys/socket.h>  // recv(), setsockopt()
#include <linux/if_packet.h> // packet_mreq
#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
#include <sys/syscall.h>
#endif
#ifdef QDOCK
#include <linux/filter.h>
#endif

////////////////////////////////////////////////////////////////////////////////
// Private functions, structures and macros
////////////////////////////////////////////////////////////////////////////////

/** @brief Linux-specific per-interface data. */
struct linux_interface_info {
    struct interface interface;

    /** @brief Index of the interface, to be used for sockaddr_ll::sll_ifindex. */
    int ifindex;

    /** @brief File descriptor of the packet socket bound to the IEEE1905 protocol. */
    int sock_1905_fd;

    /** @brief File descriptor of the packet socket bound to the LLDP protocol. */
    int sock_lldp_fd;

    uint8_t     al_mac_address[6];
    uint8_t     queue_id;
    pthread_t   thread;
};

// *********** IPC stuff *******************************************************

// Queue related function in the PLATFORM API return queue IDs that are uint8_t
// elements.
// However, in POSIX all queue related functions deal with a 'mqd_t' type.
// The following global arrays are used to store the association between a
// "PLATFORM uint8_t ID" and a "POSIX mqd_t ID"

#define MAX_QUEUE_IDS  256  // Number of values that fit in an uint8_t

#ifdef QDOCK
typedef struct _queue
{
    const char *host;
    int rx_sd;
    pthread_mutex_t tx_mutex;
    int tx_sd;
} _queue_t;
static _queue_t        queues_id[MAX_QUEUE_IDS] = {[ 0 ... MAX_QUEUE_IDS-1 ] = { NULL, -1 } };
#else
static mqd_t           queues_id[MAX_QUEUE_IDS] = {[ 0 ... MAX_QUEUE_IDS-1 ] = (mqd_t) -1};
#endif
static pthread_mutex_t queues_id_mutex          = PTHREAD_MUTEX_INITIALIZER;


// *********** Receiving packets ********************************************

static void handlePacket(uint8_t queue_id, const uint8_t *packet, size_t packet_len, mac_address interface_mac_address,
	int interface_index)
{
    uint8_t   message[13+MAX_NETWORK_SEGMENT_SIZE];
    uint16_t  message_len;
    uint8_t   message_len_msb;
    uint8_t   message_len_lsb;
    uint32_t  handling_interface_index;

    if (packet_len > MAX_NETWORK_SEGMENT_SIZE)
    {
        // This should never happen
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Recv thread* Captured packet too big\n");
        return;
    }

    if (packet_len < 2 * sizeof(mac_address))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Recv thread* Captured packet too small\n");
        return;
    }

    if (memcmp(packet, DMalMacGet(), sizeof(mac_address))
            && memcmp(packet, (uint8_t *)MCAST_1905, sizeof(mac_address))
            && memcmp(packet, (uint8_t *)MCAST_LLDP, sizeof(mac_address))
            && memcmp(packet, interface_mac_address, sizeof(mac_address)))
    {
        PLATFORM_PRINTF_DEBUG_INFO("[PLATFORM] *Recv thread* Captured packet " MACFMT " is not for us\n", MACARG(packet));
        return;
    }

    // In order to build the message that will be inserted into the queue, we
    // need to follow the "message format" defines in the documentation of
    // function 'PLATFORM_REGISTER_QUEUE_EVENT()'
    //
    message_len = packet_len + 6;
#if _HOST_IS_LITTLE_ENDIAN_ == 1
    message_len_msb = *(((uint8_t *)&message_len)+1);
    message_len_lsb = *(((uint8_t *)&message_len)+0);
#else
    message_len_msb = *(((uint8_t *)&message_len)+0);
    message_len_lsb = *(((uint8_t *)&message_len)+1);
#endif
    if (interface_index == -1)
	handling_interface_index = 0;
    else
	handling_interface_index = interface_index;

    message[0] = PLATFORM_QUEUE_EVENT_NEW_1905_PACKET;
    message[1] = message_len_msb;
    message[2] = message_len_lsb;
#if _HOST_IS_LITTLE_ENDIAN_ == 1
    message[3] = (handling_interface_index >> 24) & 0xff;
    message[4] = (handling_interface_index >> 16) & 0xff;
    message[5] = (handling_interface_index >> 8) & 0xff;
    message[6] = handling_interface_index  & 0xff;
#else
    message[3] = handling_interface_index  & 0xff;
    message[4] = (handling_interface_index >> 8) & 0xff;
    message[5] = (handling_interface_index >> 16) & 0xff;
    message[6] = (handling_interface_index >> 24) & 0xff;
#endif
    memcpy(&message[7], interface_mac_address, 6);
    memcpy(&message[13], packet, packet_len);

    // Now simply send the message.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Recv thread* Sending %d bytes to queue (0x%02x, 0x%02x, 0x%02x, 0x%02x 0x%02x, 0x%02x, 0x%02x...)\n",
	7+message_len, message[0], message[1], message[2], message[3], message[4], message[5], message[6]);

    if (0 == sendMessageToAlQueue(queue_id, message, 7 + message_len))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Receive thread* Error sending message to queue\n");
        return;
    }

    return;
}

#ifdef QDOCK
static struct sock_filter bpfcode_1905[8] = {
    //Note: the filer code is from ./tcpdump -dd 'ether proto 0x893a and !ether src a1:b2:c3:d4:e5:f6' -s 0
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 5, 0x0000893a },
    { 0x20, 0, 0, 0x00000008 },
    { 0x15, 0, 2, 0xc3d4e5f6 },
    { 0x28, 0, 0, 0x00000006 },
    { 0x15, 1, 0, 0x0000a1b2 },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};
#endif

static void *recvLoopThread(void *p)
{
    struct linux_interface_info *interface = (struct linux_interface_info *)p;
    struct packet_mreq multicast_request;
    char interface_name[IFNAMSIZ];
#ifdef QDOCK
    struct sock_fprog bpf_1905 = {8, bpfcode_1905};
#endif

    if (NULL == p)
    {
        // 'p' must point to a valid 'struct linux_interface_info'
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Recv thread* Invalid arguments in recvLoopThread()\n");

        return NULL;
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Recv thread* interface->interface.name = %s\n", interface->interface.name);
    if (isQtnWifiDevice(interface->interface.name))
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Recv thread* ni_interface_name = %s\n", ni_interface_name);
        strncpy(interface_name, ni_interface_name, IFNAMSIZ-1);
    }
    else
        strncpy(interface_name, interface->interface.name, IFNAMSIZ-1);

    interface->ifindex = getIfIndex(interface_name);

    if (-1 == interface->ifindex)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Recv thread* interface->ifindex == -1, interface_name = %s\n", interface_name);
        return NULL;
    }

#ifdef QDOCK
    /* ALL + attach the 1905 type filter */
    interface->sock_1905_fd = openPacketSocket(interface->ifindex, ETH_P_ALL);
#else
    interface->sock_1905_fd = openPacketSocket(interface->ifindex, ETHERTYPE_1905);
#endif
    if (-1 == interface->sock_1905_fd)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] socket('%s' protocol 1905) returned with errno=%d (%s) while opening a RAW socket\n",
                                    interface_name, errno, strerror(errno));
        interface->ifindex = -1;
        return NULL;
    }

#ifdef QDOCK
    // Note: replace the mac address in the rule of !ether src a1:b2:c3:d4:e5:f6' which means
    // do not self-receive the package that src address is self al_mac_address.
    bpfcode_1905[3].k = interface->al_mac_address[5] + (interface->al_mac_address[4]<<8) + \
                        (interface->al_mac_address[3]<<16) + (interface->al_mac_address[2]<<24);

    bpfcode_1905[5].k = interface->al_mac_address[1] + (interface->al_mac_address[0]<<8);

    if (-1 == setsockopt(interface->sock_1905_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_1905, sizeof(bpf_1905))) {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] setsockopt ATTACH_FILTER failed for 1905 type frames with errno=%d (%s)", errno, strerror(errno));
    }
#endif

    /* Add the AL address to this interface */
    memset(&multicast_request, 0, sizeof(multicast_request));
    multicast_request.mr_ifindex = interface->ifindex;
    multicast_request.mr_alen = 6;
    multicast_request.mr_type = PACKET_MR_UNICAST;
    memcpy(multicast_request.mr_address, interface->al_mac_address, 6);
    if (-1 == setsockopt(interface->sock_1905_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &multicast_request, sizeof(multicast_request)))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Failed to add AL MAC address to interface '%s' with errno=%d (%s)\n",
                                    interface_name, errno, strerror(errno));
    }

    /* Add the 1905 multicast address to this interface */
    multicast_request.mr_type = PACKET_MR_MULTICAST;
    memcpy(multicast_request.mr_address, MCAST_1905, 6);
    if (-1 == setsockopt(interface->sock_1905_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &multicast_request, sizeof(multicast_request)))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Failed to add 1905 multicast address to interface '%s' with errno=%d (%s)\n",
                                    interface_name, errno, strerror(errno));
    }

    /** @todo Make LLDP optional, for when lldpd is also running on the same device. */
    interface->sock_lldp_fd = openPacketSocket(interface->ifindex, ETHERTYPE_LLDP);
    if (-1 == interface->sock_lldp_fd)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] socket('%s' protocol 1905) returned with errno=%d (%s) while opening a RAW socket\n",
                                    interface_name, errno, strerror(errno));
        close(interface->sock_1905_fd);
        interface->sock_1905_fd = -1;
        interface->ifindex = -1;
        return NULL;
    }

    /* Add the LLDP multicast address to this interface */
    multicast_request.mr_type = PACKET_MR_MULTICAST;
    memcpy(multicast_request.mr_address, MCAST_LLDP, 6);
    if (-1 == setsockopt(interface->sock_lldp_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &multicast_request, sizeof(multicast_request)))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Failed to add LLDP multicast address to interface '%s' with errno=%d (%s)\n",
                                    interface_name, errno, strerror(errno));
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("Starting recv on %s\n", interface_name);
    /** @todo move to libevent instead of threads + poll */
    while(1)
    {
        struct pollfd fdset[2];
        size_t i;

        PLATFORM_PRINTF_DEBUG_DETAIL("Receiving on %s\n", interface_name);
        memset((void*)fdset, 0, sizeof(fdset));

        fdset[0].fd = interface->sock_1905_fd;
        fdset[0].events = POLLIN;
        fdset[1].fd = interface->sock_lldp_fd;
        fdset[1].events = POLLIN;

        pthread_testcancel();
        if (0 > poll(fdset, 2, -1))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Interface %s receive thread* poll() returned with errno=%d (%s)\n",
                                        interface_name, errno, strerror(errno));
            break;
        }
        pthread_testcancel();

        for (i = 0; i < ARRAY_SIZE(fdset); i++)
        {
            if (fdset[i].revents & (POLLIN|POLLERR))
            {
                uint8_t packet[MAX_NETWORK_SEGMENT_SIZE];
                ssize_t recv_length;
                struct sockaddr_ll ll;
                socklen_t fromlen;

                memset(&ll, 0, sizeof(ll));
                fromlen = sizeof(ll);
                recv_length = recvfrom(fdset[i].fd, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *)&ll, &fromlen);
                if (recv_length < 0)
                {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    {
                        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Interface %s receive thread* recv failed with errno=%d (%s) \n",
                                                    interface_name, errno, strerror(errno));
                        /* Probably not recoverable. */
                        close(interface->sock_1905_fd);
                        close(interface->sock_lldp_fd);
                        interface->sock_1905_fd = -1;
                        interface->sock_lldp_fd = -1;
                        interface->ifindex = -1;
                        return NULL;
                    }
                }
                else if (ll.sll_pkttype != PACKET_OUTGOING)
                {
                    PLATFORM_DUMP_PACKETS_INTO_FILE(DUMP_RX_PACKETS, interface->interface.name, packet, (size_t)recv_length);
                    handlePacket(interface->queue_id, packet, (size_t)recv_length, interface->interface.addr, interface->ifindex);
                }
            }
        }
    }

    // Unreachable
    PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Recv thread* Exiting thread (interface %s)\n", interface_name);
    close(interface->sock_1905_fd);
    close(interface->sock_lldp_fd);
    interface->sock_1905_fd = -1;
    interface->sock_lldp_fd = -1;
    interface->ifindex = -1;
    return NULL;
}

// *********** Timers stuff ****************************************************

// We use the POSIX timers API to implement PLATFORM timers
// It works like this:
//
//   - When the PLATFORM API user calls "PLATFORM_REGISTER_QUEUE_EVENT()" with
//     'PLATFORM_QUEUE_EVENT_TIMEOUT*', a new POSIX timer is created.
//
//   - When the timer expires, the POSIX API creates a thread for us and makes
//     it run function '_timerHandler()'
//
//   - '_timerHandler()' simply deletes (or reprograms, depending on the type
//     of timer) the timer and sends a message to a queue so that the user can
//     later be aware of the timer expiration with a call to
//     "PLATFORM_QUEUE_READ()"

struct _timerHandlerThreadData
{
    uint8_t    queue_id;
    uint32_t   token;
#if (defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)) && !defined(MUSL_LIBC)
    uint32_t   timeout_ms;
#endif
    uint8_t    periodic;
    timer_t  timer_id;
};

#if (defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)) && !defined(MUSL_LIBC)
static void *_handleTimerThread(void *p)
{
    struct _timerHandlerThreadData *aux;
    struct sigevent   sevent;
    struct itimerspec its;
    timer_t           timer_id;
    sigset_t set;
    int signum = SIGALRM;

    uint8_t   message[3+4];
    uint16_t  packet_len;
    uint8_t   packet_len_msb;
    uint8_t   packet_len_lsb;
    uint8_t   token_msb;
    uint8_t   token_2nd_msb;
    uint8_t   token_3rd_msb;
    uint8_t   token_lsb;

    PLATFORM_PRINTF_DEBUG_INFO("[PLATFORM] *Timer handler* dataptr=%p\n", p);
    aux = (struct _timerHandlerThreadData *)p;

    // First, create the timer. Note that it will be
    // destroyed if not TIMEOUT_PERIODIC
    sevent.sigev_notify = SIGEV_THREAD_ID;
    sevent._sigev_un._tid = syscall(__NR_gettid);
    sevent.sigev_signo = signum;

    sigemptyset(&set);
    sigaddset(&set, signum);
    sigprocmask(SIG_BLOCK, &set, NULL);

    if (timer_create(CLOCK_REALTIME, &sevent, &timer_id) == -1)
    {
        // Failed to create a new timer
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* timer_create failed %d (%s)\n", errno, strerror(errno));
        return NULL;
    }
    aux->timer_id = timer_id;

    its.it_value.tv_sec     = aux->timeout_ms / 1000;
    its.it_value.tv_nsec    = (aux->timeout_ms % 1000) * 1000000;
    its.it_interval.tv_sec  = aux->periodic ? its.it_value.tv_sec  : 0;
    its.it_interval.tv_nsec = aux->periodic ? its.it_value.tv_nsec : 0;

    if (0 != timer_settime(timer_id, 0, &its, NULL))
    {
        // Problems arming the timer
        //
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* timer_settime failed %d (%s)\n", errno, strerror(errno));
        timer_delete(timer_id);
        aux->timer_id = NULL;
        return NULL;
    }

    // In order to build the message that will be inserted into the queue, we
    // need to follow the "message format" defines in the documentation of
    // function 'PLATFORM_REGISTER_QUEUE_EVENT()'
    //
    packet_len = 4;

#if _HOST_IS_LITTLE_ENDIAN_ == 1
    packet_len_msb = *(((uint8_t *)&packet_len)+1);
    packet_len_lsb = *(((uint8_t *)&packet_len)+0);

    token_msb      = *(((uint8_t *)&aux->token)+3);
    token_2nd_msb  = *(((uint8_t *)&aux->token)+2);
    token_3rd_msb  = *(((uint8_t *)&aux->token)+1);
    token_lsb      = *(((uint8_t *)&aux->token)+0);
#else
    packet_len_msb = *(((uint8_t *)&packet_len)+0);
    packet_len_lsb = *(((uint8_t *)&packet_len)+1);

    token_msb     = *(((uint8_t *)&aux->token)+0);
    token_2nd_msb = *(((uint8_t *)&aux->token)+1);
    token_3rd_msb = *(((uint8_t *)&aux->token)+2);
    token_lsb     = *(((uint8_t *)&aux->token)+3);
#endif

    message[0] = 1 == aux->periodic ? PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC : PLATFORM_QUEUE_EVENT_TIMEOUT;
    message[1] = packet_len_msb;
    message[2] = packet_len_lsb;
    message[3] = token_msb;
    message[4] = token_2nd_msb;
    message[5] = token_3rd_msb;
    message[6] = token_lsb;

    while(1)
    {
         if (sigwait(&set, &signum) == -1)
         {
             // Problems arming the timer
             //
             PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* sigwait failed\n");
             timer_delete(timer_id);
             aux->timer_id = NULL;
             return NULL;
         }

         PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Timer handler* Sending %d bytes to queue (%02x, %02x, %02x, ...)\n", 3+packet_len, message[0], message[1], message[2]);

         if (0 == sendMessageToAlQueue(aux->queue_id, message, 3+packet_len))
         {
             PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* Error sending message to queue from _timerHandler()\n");
         }

         if (1 == aux->periodic)
         {
             // Periodic timer are automatically re-armed. We don't need to do
             // anything
         }
         else
         {
             // Delete the asociater timer
             //
             timer_delete(aux->timer_id);

             // Free 'struct _timerHandlerThreadData', as we don't need it any more
             //
             free(aux);
             break;
         }
    }

    return NULL;
}
#else
static void _timerHandler(union sigval s)
{
    struct _timerHandlerThreadData *aux;

    uint8_t   message[3+4];
    uint16_t  packet_len;
    uint8_t   packet_len_msb;
    uint8_t   packet_len_lsb;
    uint8_t   token_msb;
    uint8_t   token_2nd_msb;
    uint8_t   token_3rd_msb;
    uint8_t   token_lsb;

    aux = (struct _timerHandlerThreadData *)s.sival_ptr;

    // In order to build the message that will be inserted into the queue, we
    // need to follow the "message format" defines in the documentation of
    // function 'PLATFORM_REGISTER_QUEUE_EVENT()'
    //
    packet_len = 4;

#if _HOST_IS_LITTLE_ENDIAN_ == 1
    packet_len_msb = *(((uint8_t *)&packet_len)+1);
    packet_len_lsb = *(((uint8_t *)&packet_len)+0);

    token_msb      = *(((uint8_t *)&aux->token)+3);
    token_2nd_msb  = *(((uint8_t *)&aux->token)+2);
    token_3rd_msb  = *(((uint8_t *)&aux->token)+1);
    token_lsb      = *(((uint8_t *)&aux->token)+0);
#else
    packet_len_msb = *(((uint8_t *)&packet_len)+0);
    packet_len_lsb = *(((uint8_t *)&packet_len)+1);

    token_msb     = *(((uint8_t *)&aux->token)+0);
    token_2nd_msb = *(((uint8_t *)&aux->token)+1);
    token_3rd_msb = *(((uint8_t *)&aux->token)+2);
    token_lsb     = *(((uint8_t *)&aux->token)+3);
#endif

    message[0] = 1 == aux->periodic ? PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC : PLATFORM_QUEUE_EVENT_TIMEOUT;
    message[1] = packet_len_msb;
    message[2] = packet_len_lsb;
    message[3] = token_msb;
    message[4] = token_2nd_msb;
    message[5] = token_3rd_msb;
    message[6] = token_lsb;

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Timer handler* Sending %d bytes to queue (%02x, %02x, %02x, ...)\n", 3+packet_len, message[0], message[1], message[2]);

    if (0 == sendMessageToAlQueue(aux->queue_id, message, 3+packet_len))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Timer handler* Error sending message to queue from _timerHandler()\n");
    }

    if (1 == aux->periodic)
    {
        // Periodic timer are automatically re-armed. We don't need to do
        // anything
    }
    else
    {
        // Delete the asociater timer
        //
        timer_delete(aux->timer_id);

        // Free 'struct _timerHandlerThreadData', as we don't need it any more
        //
        free(aux);
    }

    return;
}
#endif


// *********** Push button stuff ***********************************************

// Pressing the button can be simulated by "touching" (ie. updating the
// timestamp) the following tmp file
//
#define PUSH_BUTTON_VIRTUAL_FILENAME  "/tmp/virtual_push_button"

// For those platforms with a physical buttons attached to a GPIO, we need to
// know the actual GPIO number (as seen by the Linux kernel) to use.
//
//     NOTE: "PUSH_BUTTON_GPIO_NUMBER" is a string, not a number. It will later
//     be used in a string context, thus the "" are needed.
//     It can take the string representation of a number (ex: "26") or the
//     special value "disable", meaning we don't have GPIO support.
//
//#define PUSH_BUTTON_GPIO_NUMBER              "disable" //"26"

#ifdef PUSH_BUTTON_GPIO_NUMBER
#define PUSH_BUTTON_GPIO_EXPORT_FILENAME     "/sys/class/gpio/export"
#define PUSH_BUTTON_GPIO_DIRECTION_FILENAME  "/sys/class/gpio/gpio"PUSH_BUTTON_GPIO_NUMBER"/direction"
#define PUSH_BUTTON_GPIO_VALUE_FILENAME      "/sys/class/gpio/gpio"PUSH_BUTTON_GPIO_NUMBER"/direction"
#endif

// The only information that needs to be sent to the new thread is the "queue
// id" to later post messages to the queue.
//
struct _pushButtonThreadData
{
    uint8_t     queue_id;
};

static void *_pushButtonThread(void *p)
{
    // In this implementation we will send the "push button" configuration
    // event message to the queue when either:
    //
    //   a) The user presses a physical button associated to a GPIO whose number
    //      is "PUSH_BUTTON_GPIO_NUMBER" (ie. it is exported by the linux kernel
    //      in "/sys/class/gpio/gpioXXX", where "XXX" is
    //      "PUSH_BUTTON_GPIO_NUMBER")
    //
    //   b) The user updates the timestamp of a tmp file called
    //      "PUSH_BUTTON_VIRTUAL_FILENAME".
    //      This is useful for debugging and for supporting the "push button"
    //      mechanism in those platforms without a physical button.
    //
    // This thread will simply wait for activity on any of those two file
    // descriptors and then send the "push button" configuration event to the
    // AL queue.
    // How is this done?
    //
    //   1. Configure the GPIO as input.
    //   2. Create an "inotify" watch on the tmp file.
    //   3. Use "poll()" to wait for either changes in the value of the GPIO or
    //      timestamp updates in the tmp file.

#ifdef PUSH_BUTTON_GPIO_NUMBER
    FILE  *fd_gpio;
    FILE  *fd_tmp;
    int gpio_set_id = -1;
    int  fdraw_gpio;
#endif
#ifdef PUSH_BUTTON_VIRTUAL_FILENAME
    int  fdraw_tmp;
    int  fd_watched;
    int  virtual_set_id = -1;
#endif

#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
    int  fd_qsr1000 = -1;
    int  qsr_set_id = -1;
#endif
    struct pollfd fdset[3];

    uint8_t queue_id;

    queue_id = ((struct _pushButtonThreadData *)p)->queue_id;;

#ifdef PUSH_BUTTON_GPIO_NUMBER
    // First of all, prepare the GPIO kernel descriptor for "reading"...
    //
    {

        // 1. Write the number of the GPIO where the physical button is
        //    connected to file "/sys/class/gpio/export".
        //    This will instruct the Linux kernel to create a folder named
        //    "/sys/class/gpio/gpioXXX" that we can later use to read the GPIO
        //    level.
        //
        if (NULL == (fd_gpio = fopen(PUSH_BUTTON_GPIO_EXPORT_FILENAME, "w")))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error opening GPIO fd %s\n", PUSH_BUTTON_GPIO_EXPORT_FILENAME);
            return NULL;
        }
        if (0 == fwrite(PUSH_BUTTON_GPIO_NUMBER, 1, strlen(PUSH_BUTTON_GPIO_NUMBER), fd_gpio))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error writing '"PUSH_BUTTON_GPIO_NUMBER"' to %s\n", PUSH_BUTTON_GPIO_EXPORT_FILENAME);
            fclose(fd_gpio);
            return NULL;
        }
        fclose(fd_gpio);

        // 2. Write "in" to file "/sys/class/gpio/gpioXXX/direction" to tell the
        //    kernel that this is an "input" GPIO (ie. we are only going to
        //    read -and not write- its value).

        if (NULL == (fd_gpio = fopen(PUSH_BUTTON_GPIO_DIRECTION_FILENAME, "w")))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error opening GPIO fd %s\n", PUSH_BUTTON_GPIO_DIRECTION_FILENAME);
            return NULL;
        }
        if (0 == fwrite("in", 1, strlen("in"), fd_gpio))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error writing 'in' to %s\n", PUSH_BUTTON_GPIO_DIRECTION_FILENAME);
            fclose(fd_gpio);
            return NULL;
        }
        fclose(fd_gpio);
    }

    // ... and then re-open the GPIO file descriptors for reading in "raw"
    // (ie "open" instead of "fopen") mode.
    //
    {
        if (-1  == (fdraw_gpio = open(PUSH_BUTTON_GPIO_VALUE_FILENAME, O_RDONLY | O_NONBLOCK)))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error opening GPIO fd %s\n", PUSH_BUTTON_GPIO_VALUE_FILENAME);
        }
    }

    // Next, regarding the "virtual" button, first create the "tmp" file in
    // case it does not already exist...
    //
    if (NULL == (fd_tmp = fopen(PUSH_BUTTON_VIRTUAL_FILENAME, "w+")))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Could not create tmp file %s\n", PUSH_BUTTON_VIRTUAL_FILENAME);
    }
    else
    {
        fclose(fd_tmp);
    }
#endif

#ifdef PUSH_BUTTON_VIRTUAL_FILENAME
    // ...and then add a "watch" that triggers when its timestamp changes (ie.
    // when someone does a "touch" of the file or writes to it, for example).
    //
    if (-1 == (fdraw_tmp = inotify_init()))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* inotify_init() returned with errno=%d (%s)\n", errno, strerror(errno));
    }
    else if ((fd_watched = inotify_add_watch(fdraw_tmp, PUSH_BUTTON_VIRTUAL_FILENAME, IN_ATTRIB) < 0))
    {
        PLATFORM_PRINTF_DEBUG_INFO("[PLATFORM] *Push button thread* inotify_add_watch() returned with errno=%d (%s)\n", errno, strerror(errno));
    }
#endif

#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
    fd_qsr1000 = qsr1000_init_push_button();
    if (fd_qsr1000 < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* init for qsr1000 returned failed \n");
    }
#endif

    // At this point we have two file descriptors ("fdraw_gpio" and "fdraw_tmp")
    // that we can monitor with a call to "poll()"
    //
    while(1)
    {
        int   nfds = 0;
        uint8_t button_pressed;

        memset((void*)fdset, 0, sizeof(fdset));

#ifdef PUSH_BUTTON_VIRTUAL_FILENAME
        if (fdraw_tmp >= 0 && fd_watched >= 0)
        {
            fdset[nfds].fd     = fdraw_tmp;
            fdset[nfds].events = POLLIN;
            virtual_set_id = nfds++;
        }
#endif

#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
        if (fd_qsr1000 >= 0)
        {
            fdset[nfds].fd     = fd_qsr1000;
            fdset[nfds].events = POLLIN;
            qsr_set_id = nfds++;
        }
#endif

#ifdef PUSH_BUTTON_GPIO_NUMBER
        if (fdraw_gpio >= 0)
        {
            fdset[nfds].fd     = fdraw_gpio;
            fdset[nfds].events = POLLPRI;
            gpio_set_id = nfds++;
        }
#endif

        // The thread will block here (forever, timeout = -1), until there is
        // a change in one of the two file descriptors ("changes" in the "tmp"
        // file fd are cause by "attribute" changes -such as the timestamp-,
        // while "changes" in the GPIO fd are caused by a value change in the
        // GPIO value).
        //
        if (0 > poll(fdset, nfds, -1))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* poll() returned with errno=%d (%s)\n", errno, strerror(errno));
            break;
        }

        button_pressed = 0;

#ifdef PUSH_BUTTON_VIRTUAL_FILENAME
        if (virtual_set_id >= 0 && (fdset[virtual_set_id].revents & POLLIN))
        {
            struct inotify_event event;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Virtual button has been pressed!\n");
            button_pressed = 1;

            // We must "read()" from the "tmp" fd to "consume" the event, or
            // else the next call to "poll() won't block.
            //
            while (read(fdraw_tmp, &event, sizeof(event)) < 0)
            {
                if (errno != EAGAIN)
                    break;
            }
        }
#endif

#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
        if (qsr_set_id >= 0 && (fdset[qsr_set_id].revents & POLLIN))
        {
            // TODO: QTNA
            // if event is "WPS-BUTTON.indication", set button_pressed
            button_pressed = qsr1000_check_button_pressed(fd_qsr1000);
        }
#endif

#ifdef PUSH_BUTTON_GPIO_NUMBER
        if (gpio_set_id >= 0 && (fdset[gpio_set_id].revents & POLLPRI))
        {
            char buf[3];

            if (-1 == read(fdraw_gpio, buf, 3))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* read() returned with errno=%d (%s)\n", errno, strerror(errno));
                continue;
            }

            if (buf[0] == '1')
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Physical button has been pressed!\n");
                button_pressed = 1;
            }
        }
#endif

        if (1 == button_pressed)
        {
            uint8_t   message[3];

            message[0] = PLATFORM_QUEUE_EVENT_PUSH_BUTTON;
            message[1] = 0x0;
            message[2] = 0x0;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Push button thread* Sending 3 bytes to queue (0x%02x, 0x%02x, 0x%02x)\n", message[0], message[1], message[2]);

            if (0 == sendMessageToAlQueue(queue_id, message, 3))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Push button thread* Error sending message to queue from _pushButtonThread()\n");
            }
        }
    }

    // Close file descriptors and exit
    //
#ifdef PUSH_BUTTON_VIRTUAL_FILENAME
    if (fdraw_tmp >= 0)
    {
        if (fd_watched >= 0)
            inotify_rm_watch(fdraw_tmp, fd_watched);
        close(fdraw_tmp);
    }
#endif
#if defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)
    qsr1000_deinit_push_button(fd_qsr1000);
#endif
#ifdef PUSH_BUTTON_GPIO_NUMBER
    if (fdraw_gpio >= 0)
        close(fdraw_gpio);
#endif

    PLATFORM_PRINTF_DEBUG_INFO("[PLATFORM] *Push button thread* Exiting...\n");

    free(p);
    return NULL;
}

// *********** Topology change notification stuff ******************************

// The platform notifies the 1905 that a topology change has just took place
// by "touching" the following tmp file
//
#define TOPOLOGY_CHANGE_NOTIFICATION_FILENAME  "/tmp/topology_change"

// The only information that needs to be sent to the new thread is the "queue
// id" to later post messages to the queue.
//
struct _topologyMonitorThreadData
{
    uint8_t     queue_id;
};

static void *_topologyMonitorThread(void *p)
{
    FILE  *fd_tmp;

    int  fdraw_tmp;

    struct pollfd fdset[2];

    uint8_t  queue_id;

    queue_id = ((struct _topologyMonitorThreadData *)p)->queue_id;

    // Regarding the "virtual" notification system, first create the "tmp" file
    // in case it does not already exist...
    //
    if (NULL == (fd_tmp = fopen(TOPOLOGY_CHANGE_NOTIFICATION_FILENAME, "w+")))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* Could not create tmp file %s\n", TOPOLOGY_CHANGE_NOTIFICATION_FILENAME);
        return NULL;
    }
    fclose(fd_tmp);

    // ...and then add a "watch" that triggers when its timestamp changes (ie.
    // when someone does a "touch" of the file or writes to it, for example).
    //
    if (-1 == (fdraw_tmp = inotify_init()))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* inotify_init() returned with errno=%d (%s)\n", errno, strerror(errno));
        return NULL;
    }
    if (-1 == inotify_add_watch(fdraw_tmp, TOPOLOGY_CHANGE_NOTIFICATION_FILENAME, IN_ATTRIB))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* inotify_add_watch() returned with errno=%d (%s)\n", errno, strerror(errno));
        return NULL;
    }

    while (1)
    {
        int   nfds;
        uint8_t notification_activated;

        memset((void*)fdset, 0, sizeof(fdset));

        fdset[0].fd     = fdraw_tmp;
        fdset[0].events = POLLIN;
        nfds            = 1;

        // TODO: Other fd's to detect topoly changes would be initialized here.
        // One good idea would be to use a NETLINK socket that is notified by
        // the Linux kernel when network "stuff" (routes, IPs, ...) change.
        //
        //fdset[0].fd     = ...;
        //fdset[0].events = POLLIN;
        //nfds            = 2;

        // The thread will block here (forever, timeout = -1), until there is
        // a change in one of the previous file descriptors .
        //
        if (0 > poll(fdset, nfds, -1))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* poll() returned with errno=%d (%s)\n", errno, strerror(errno));
            break;
        }

        notification_activated = 0;

        if (fdset[0].revents & POLLIN)
        {
            struct inotify_event event;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Topology change monitor thread* Virtual notification has been activated!\n");
            notification_activated = 1;

            // We must "read()" from the "tmp" fd to "consume" the event, or
            // else the next call to "poll() won't block.
            //
            while (read(fdraw_tmp, &event, sizeof(event)) < 0)
            {
                if (errno != EAGAIN)
                    break;
            }
        }

        if (1 == notification_activated)
        {
            uint8_t  message[3];

            message[0] = PLATFORM_QUEUE_EVENT_TOPOLOGY_CHANGE_NOTIFICATION;
            message[1] = 0x0;
            message[2] = 0x0;

            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Topology change monitor thread* Sending 3 bytes to queue (0x%02x, 0x%02x, 0x%02x)\n", message[0], message[1], message[2]);

            if (0 == sendMessageToAlQueue(queue_id, message, 3))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] *Topology change monitor thread* Error sending message to queue from _pushButtonThread()\n");
            }
        }
    }

    PLATFORM_PRINTF_DEBUG_INFO("[PLATFORM] *Topology change monitor thread* Exiting...\n");

    free(p);
    return NULL;
}

#ifdef QDOCK
int getSdFromQueueId(uint8_t queue_id)
{
    if (NULL == queues_id[queue_id].host)
        return -1;
    return queues_id[queue_id].rx_sd;
}

uint8_t getQueueIdFomrSd(int sd)
{
    int i;

    if (sd < 0)
        return 0;

    pthread_mutex_lock(&queues_id_mutex);
    for (i=1; i<MAX_QUEUE_IDS; i++)  // Note: "0" is not a valid "queue_id"
    {                                // according to the documentation of
        if (sd == queues_id[i].rx_sd)
        {
            break;
        }
    }
    pthread_mutex_unlock(&queues_id_mutex);
    if (MAX_QUEUE_IDS == i)
        i = 0;
    return i;
}
#endif

////////////////////////////////////////////////////////////////////////////////
// Internal API: to be used by other platform-specific files (functions
// declaration is found in "./platform_os_priv.h")
////////////////////////////////////////////////////////////////////////////////

uint8_t sendMessageToAlQueue(uint8_t queue_id, uint8_t *message, uint16_t message_len)
{
#ifdef QDOCK
    struct sockaddr_un addr;
    socklen_t addr_len;
    int ret;
    _queue_t mqdes;
#else
    mqd_t   mqdes;
#endif

    mqdes = queues_id[queue_id];
#ifdef QDOCK
    if (NULL == mqdes.host)
#else
    if ((mqd_t) -1 == mqdes)
#endif
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Invalid queue ID(%d)\n", queue_id);
        return 0;
    }

    if (NULL == message)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] Invalid message\n");
        return 0;
    }

#ifdef QDOCK
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, mqdes.host, sizeof(addr.sun_path) - 1);
    addr_len = sizeof(addr);

    pthread_mutex_lock(&mqdes.tx_mutex);
    ret = sendto(mqdes.tx_sd, message, message_len, 0, (struct sockaddr *)&addr, addr_len);
    pthread_mutex_unlock(&mqdes.tx_mutex);
    if (ret < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] sendto('%d') returned with errno=%d (%s)\n", queue_id, errno, strerror(errno));
        return 0;
    }
#else
    if (0 !=  mq_send(mqdes, (const char *)message, message_len, 0))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_send('%d') returned with errno=%d (%s)\n", queue_id, errno, strerror(errno));
        return 0;
    }
#endif

    return 1;
}


////////////////////////////////////////////////////////////////////////////////
// Platform API: Device information functions to be used by platform-independent
// files (functions declarations are  found in "../interfaces/platform_os.h)
////////////////////////////////////////////////////////////////////////////////

struct deviceInfo *PLATFORM_GET_DEVICE_INFO(void)
{
    // TODO: Retrieve real data from OS

    static struct deviceInfo x =
    {
        .friendly_name      = "Kitchen ice cream dispatcher",
        .manufacturer_name  = "Megacorp S.A.",
        .manufacturer_model = "Ice cream dispatcher X-2000",

        .control_url        = "http://192.168.10.44",
    };

    return &x;
}

#ifdef QDOCK
static int _createUnixSocket(const char *name)
{
    int sd;
    struct sockaddr_un addr;

    sd = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sd < 0) {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] unix sock('%s') open failed errno=%d (%s)\n", name, errno, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name, sizeof(addr.sun_path) - 1);
    unlink(addr.sun_path);
    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] unix sock('%s') bind failed errno=%d (%s)\n", name, errno, strerror(errno));
        close(sd);
        return -1;
    }

    return sd;
}
#endif

////////////////////////////////////////////////////////////////////////////////
// Platform API: IPC related functions to be used by platform-independent
// files (functions declarations are  found in "../interfaces/platform_os.h)
////////////////////////////////////////////////////////////////////////////////

uint8_t PLATFORM_CREATE_QUEUE(const char *name)
{
    int            i;
#ifdef QDOCK
#else
    mqd_t          mqdes;
    struct mq_attr attr;
#endif
    char           name_tmp[20];

#ifdef QDOCK
    if (!name)
        return 0;
#endif

    pthread_mutex_lock(&queues_id_mutex);

    for (i=1; i<MAX_QUEUE_IDS; i++)  // Note: "0" is not a valid "queue_id"
    {                                // according to the documentation of
#ifdef QDOCK
        if (NULL == queues_id[i].host)
#else
        if (-1 == queues_id[i])      // "PLATFORM_CREATE_QUEUE()". That's why we
#endif
        {                            // skip it
            // Empty slot found.
            //
            break;
        }
    }
    if (MAX_QUEUE_IDS == i)
    {
        // No more queue id slots available
        //
        pthread_mutex_unlock(&queues_id_mutex);
        return 0;
    }

#ifdef QDOCK
    queues_id[i].rx_sd = _createUnixSocket(name);
    if (queues_id[i].rx_sd < 0)
    {
        pthread_mutex_unlock(&queues_id_mutex);
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] unix sock('%s') for rx create failed\n", name);
        return 0;
    }
    snprintf(name_tmp, 20, "%s_client", name);
    unlink(name_tmp);
    queues_id[i].tx_sd = _createUnixSocket(name_tmp);
    if (queues_id[i].tx_sd < 0)
    {
        pthread_mutex_unlock(&queues_id_mutex);
        close(queues_id[i].rx_sd);
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] unix sock('%s') for tx create failed\n", name_tmp);
        return 0;
    }
    pthread_mutex_init(&queues_id[i].tx_mutex, NULL);
    queues_id[i].host = name;
    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] unix sock %u/%u created for '%s'\n", queues_id[i].rx_sd, queues_id[i].tx_sd, name);
#else
    if (!name)
    {
        name_tmp[0] = 0x0;
        sprintf(name_tmp, "/queue_%03d", i);
        name = name_tmp;
    }
    else if (name[0] != '/')
    {
        snprintf(name_tmp, 20, "/%s", name);
        name = name_tmp;
    }

    // If a queue with this name already existed (maybe from a previous
    // session), destroy and re-create it
    //
    mq_unlink(name);

    attr.mq_flags   = 0;
    attr.mq_maxmsg  = 100;
    attr.mq_curmsgs = 0;
    attr.mq_msgsize = MAX_NETWORK_SEGMENT_SIZE+3;
      //
      // NOTE: The biggest value in the queue is going to be a message from the
      // "new packet" event, which is MAX_NETWORK_SEGMENT_SIZE+3 bytes long.
      // The "PLATFORM_CREATE_QUEUE()" documentation mentions

    if ((mqd_t) -1 == (mqdes = mq_open(name, O_RDWR | O_CREAT, 0666, &attr)))
    {
        // Could not create queue
        //
        pthread_mutex_unlock(&queues_id_mutex);
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_open('%s') returned with errno=%d (%s)\n", name, errno, strerror(errno));
        return 0;
    }

    queues_id[i] = mqdes;
#endif

    pthread_mutex_unlock(&queues_id_mutex);
    return i;
}

uint8_t PLATFORM_REGISTER_QUEUE_EVENT_NEW_1905_PACKET(uint8_t queue_id, struct interface *interface)
{
    struct linux_interface_info *intf_info = interface->interface_info;

    if (NULL == intf_info)
    {
        intf_info = (struct linux_interface_info *)malloc(sizeof(struct linux_interface_info));
        if (NULL == intf_info)
            // Out of memory
            //
            return 0;
        intf_info->sock_1905_fd = -1;
        intf_info->sock_lldp_fd = -1;
        intf_info->ifindex = -1;
    }

    if (intf_info->ifindex == -1)
    {
        intf_info->queue_id              = queue_id;
        intf_info->interface             = *interface;
        memcpy(intf_info->al_mac_address, interface->owner->al_mac_addr, 6);

        pthread_create(&intf_info->thread, NULL, recvLoopThread, (void *)intf_info);

        interface->interface_info = intf_info;
    }

    return 1;
}

uint8_t PLATFORM_UNREGISTER_QUEUE_EVENT_NEW_1905_PACKET(uint8_t queue_id, struct interface *interface)
{
    struct linux_interface_info *intf_info = interface->interface_info;

    if (intf_info)
    {
        if (intf_info->ifindex != -1)
        {
            pthread_cancel(intf_info->thread);
            pthread_join(intf_info->thread, NULL);
        }

        if (intf_info->sock_1905_fd != -1)
            close(intf_info->sock_1905_fd);
        if (intf_info->sock_lldp_fd != -1)
            close(intf_info->sock_lldp_fd);

        free(intf_info);
        interface->interface_info = NULL;
    }

    return 1;
}

uint8_t PLATFORM_REGISTER_QUEUE_EVENT(uint8_t queue_id, uint8_t event_type, void *data)
{
    switch (event_type)
    {
        case PLATFORM_QUEUE_EVENT_NEW_1905_PACKET:
        {
            struct event1905Packet           *p1;
            struct linux_interface_info      *interface;

            if (NULL == data)
            {
                // 'data' must contain a pointer to a 'struct event1905Packet'
                //
                return 0;
            }

            p1 = (struct event1905Packet *)data;

            interface = (struct linux_interface_info *)malloc(sizeof(struct linux_interface_info));
            if (NULL == interface)
            {
                // Out of memory
                //
                return 0;
            }

            interface->queue_id              = queue_id;
            interface->interface.name        = strdup(p1->interface_name);
            memcpy(interface->interface.addr,         p1->interface_mac_address, 6);
            memcpy(interface->al_mac_address,         p1->al_mac_address,        6);

            pthread_create(&interface->thread, NULL, recvLoopThread, (void *)interface);

            /** @todo This is a horrible hack to make sure the addresses are configured on the interfaces before we
             * start sending raw packets. */
            usleep(30000);

            // NOTE:
            //   The memory allocated by "interface" will be lost forever at this
            //   point (well... until the application exits, that is).
            //   This is considered acceptable.

            break;
        }

        case PLATFORM_QUEUE_EVENT_NEW_ALME_MESSAGE:
        {
            // The AL entity is telling us that it is capable of processing ALME
            // messages and that it wants to receive ALME messages on the
            // provided queue.
            //
            // In our platform-dependent implementation, we have decided that
            // ALME messages are going to be received on a dedicated thread
            // that runs a TCP server.
            //
            // What we are going to do now is:
            //
            //   1) Create that thread
            //
            //   2) Tell it that everytime a new packet containing ALME
            //      commands arrives on its socket it should forward the
            //      payload to this queue.
            //
            pthread_t                thread;
            struct almeServerThreadData  *p;

            p = (struct almeServerThreadData *)malloc(sizeof(struct almeServerThreadData));
            if (NULL == p)
            {
                // Out of memory
                //
                return 0;
            }
            p->queue_id = queue_id;

            pthread_create(&thread, NULL, almeServerThread, (void *)p);

            break;
        }

        case PLATFORM_QUEUE_EVENT_TIMEOUT:
        case PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC:
        {
#if (defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)) && !defined(MUSL_LIBC)
            pthread_t                      thread;
#endif
            struct eventTimeOut             *p1;
            struct _timerHandlerThreadData  *p2;
#if !(defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)) || defined(MUSL_LIBC)
            struct sigevent      se;
            struct itimerspec    its;
            timer_t              timer_id;
#endif

            p1 = (struct eventTimeOut *)data;

            if (p1->token > MAX_TIMER_TOKEN)
            {
                // Invalid arguments
                //
                return 0;
            }

            p2 = (struct _timerHandlerThreadData *)malloc(sizeof(struct _timerHandlerThreadData));
            if (NULL == p2)
            {
                // Out of memory
                //
                return 0;
            }

            p2->queue_id    = queue_id;
            p2->token       = p1->token;
#if (defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)) && !defined(MUSL_LIBC)
            p2->timeout_ms  = p1->timeout_ms;
#endif
            p2->periodic    = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC == event_type ? 1 : 0;

#if (defined(_FLAVOUR_QSR1000_) || defined(_FLAVOUR_QSR10K_)) && !defined(MUSL_LIBC)
            pthread_create(&thread, NULL, _handleTimerThread, (void *)p2);
#else
            // Next, create the timer. Note that it will be automatically
            // destroyed (by us) in the callback function
            //
            memset(&se, 0, sizeof(se));
            se.sigev_notify          = SIGEV_THREAD;
            se.sigev_notify_function = _timerHandler;
            se.sigev_value.sival_ptr = (void *)p2;

            if (-1 == timer_create(CLOCK_REALTIME, &se, &timer_id))
            {
                // Failed to create a new timer
                //
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM]timer_create failed %d (%s)\n", errno, strerror(errno));
                free(p2);
                return 0;
            }
            p2->timer_id = timer_id;

            // Finally, arm/start the timer
            //
            its.it_value.tv_sec     = p1->timeout_ms / 1000;
            its.it_value.tv_nsec    = (p1->timeout_ms % 1000) * 1000000;
            its.it_interval.tv_sec  = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC == event_type ? its.it_value.tv_sec  : 0;
            its.it_interval.tv_nsec = PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC == event_type ? its.it_value.tv_nsec : 0;

            if (0 != timer_settime(timer_id, 0, &its, NULL))
            {
                // Problems arming the timer
                //
                PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM]timer_settime failed %d (%s)\n", errno, strerror(errno));
                free(p2);
                timer_delete(timer_id);
                return 0;
            }
#endif

            break;
        }

        case PLATFORM_QUEUE_EVENT_PUSH_BUTTON:
        {
            // The AL entity is telling us that it is capable of processing
            // "push button" configuration events.
            //
            // Create the thread in charge of generating these events.
            //
            pthread_t                      thread;
            struct _pushButtonThreadData  *p;

            p = (struct _pushButtonThreadData *)malloc(sizeof(struct _pushButtonThreadData));
            if (NULL == p)
            {
                // Out of memory
                //
                return 0;
            }

            p->queue_id = queue_id;
            pthread_create(&thread, NULL, _pushButtonThread, (void *)p);

            break;
        }

        case PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK:
        {
            // The AL entity is telling us that it is capable of processing
            // "authenticated link" events.
            //
            // We don't really need to do anything here. The interface specific
            // thread will be created when the AL entity calls the
            // "PLATFORM_START_PUSH_BUTTON_CONFIGURATION()" function.

            break;
        }

        case PLATFORM_QUEUE_EVENT_TOPOLOGY_CHANGE_NOTIFICATION:
        {
            // The AL entity is telling us that it is capable of processing
            // "topology change" events.
            //
            // We will create a new thread in charge of monitoring the local
            // topology to generate these events.
            //
            pthread_t                           thread;
            struct _topologyMonitorThreadData  *p;

            p = (struct _topologyMonitorThreadData *)malloc(sizeof(struct _topologyMonitorThreadData));
            if (NULL == p)
            {
                // Out of memory
                //
                return 0;
            }

            p->queue_id = queue_id;

            pthread_create(&thread, NULL, _topologyMonitorThread, (void *)p);

            break;
        }

        default:
        {
            // Unknown event type!!
            //
            return 0;
        }
    }

    return 1;
}

uint8_t PLATFORM_READ_QUEUE(uint8_t queue_id, uint8_t *message_buffer)
{
#ifdef QDOCK
    _queue_t mqdes;
#else
    mqd_t    mqdes;
#endif
    ssize_t  len;
    int adjust_len = 3;

    mqdes = queues_id[queue_id];
#ifdef QDOCK
    if (NULL == mqdes.host
        || mqdes.rx_sd < 0)
#else
    if ((mqd_t) -1 == mqdes)
#endif
    {
        // Invalid ID
        return 1;
    }

#ifdef QDOCK
    len = recv(mqdes.rx_sd, message_buffer, MAX_NETWORK_SEGMENT_SIZE+13, MSG_DONTWAIT);
    if (len <= 0)
#else
    len = mq_receive(mqdes, (char *)message_buffer, MAX_NETWORK_SEGMENT_SIZE+13, NULL);

    if (-1 == len)
#endif
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_receive() returned with errno=%d (%s)\n", errno, strerror(errno));
        return 0;
    }

    // All messages are TLVs where the second and third bytes indicate the
    // total length of the payload. This value *must* match "len-3"
    //
    if ( len < 3 )
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_receive() returned than 3 bytes (minimum TLV size)\n");
        return 0;
    }
    else
    {
        uint16_t payload_len;

        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] Receiving %d bytes from queue (%02x, %02x, %02x, ...)\n", (unsigned)len, message_buffer[0], message_buffer[1], message_buffer[2]);

        payload_len = *(((uint8_t *)message_buffer)+1) * 256 + *(((uint8_t *)message_buffer)+2);

	if (message_buffer[0] == PLATFORM_QUEUE_EVENT_NEW_1905_PACKET)
		adjust_len = 7;
        if (payload_len != (len-adjust_len))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] mq_receive() returned %d bytes, but the TLV is %d bytes\n", (unsigned)len, payload_len+adjust_len);
            return 0;
        }
    }

    return 1;
}

uint8_t PLATFORM_FIND_QUEUE_ID_BY_NAME(const char *name)
{
    int i;
    pthread_mutex_lock(&queues_id_mutex);
    for (i = 1; i < MAX_QUEUE_IDS; i++)  // Note: "0" is not a valid "queue_id"
    {
        if (queues_id[i].host == NULL)
            continue;
        if (0 == strncmp(queues_id[i].host, name, strlen(queues_id[i].host)))
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("%s found %s queue_id %d\n", __func__, queues_id[i].host, i);
            pthread_mutex_unlock(&queues_id_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&queues_id_mutex);
    return 0;
}
