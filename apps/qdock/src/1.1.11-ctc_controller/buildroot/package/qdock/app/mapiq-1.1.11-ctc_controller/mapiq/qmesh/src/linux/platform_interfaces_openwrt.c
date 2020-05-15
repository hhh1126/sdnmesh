/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
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

#include "../platform_interfaces.h"
#include "platform_interfaces_priv.h"
#include "platform_os_priv.h"

#include <stdio.h>      // printf(), popen()
#include <stdlib.h>     // malloc(), ssize_t
#include <string.h>     // strdup()
#include <errno.h>      // errno
#include <pthread.h>    // mutex functions


////////////////////////////////////////////////////////////////////////////////
// Private data and functions
////////////////////////////////////////////////////////////////////////////////

// OpenWRT includes the "UCI" configuration system to centralize in a single
// place all the configurability "needs" the user might have.
//
// It works like this:
//
//   - There is a special folder ("/etc/config") containing configuration files
//     for most of the OpenWRT components.
//
//   - These files are "mapped" to the real configuration files of each
//     component. So, for example, if you change "/etc/config/system" to update
//     the "hostname" paramete, UCI knows which other file really needs to be
//     modified (in this case "/etc/hostname") for the change to be effective.
//
//   - In addition, there is a command ("uci") than can be invoked to update
//     these file in "/etc/config" and reload the corresponding subsystems.
//
// The UCI subsystem is explained in great detail in the official OpenWRT wiki:
//
//   https://wiki.openwrt.org/doc/uci
//
// In order to obtain information of the UCI subsytem of apply a desired
// configuration setting we will use the following functions than simply
// execute the "uci" command and wait for a response.

// Mutex to avoid concurrent UCI access
//
pthread_mutex_t uci_mutex = PTHREAD_MUTEX_INITIALIZER;

static char * _read_uci_parameter_value(char * parameter)
{
    FILE    *pipe ;
    char    *line;
    size_t   len;
    char command[200] = "";

    strcat(command,"uci get ");
    strcat(command, parameter);

    // Execute the UCI query command.
    //
    pthread_mutex_lock(&uci_mutex);
    pipe = popen(command, "r");

    if (!pipe)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] popen() returned with errno=%d (%s)\n", errno, strerror(errno));
        pthread_mutex_unlock(&uci_mutex);
        return NULL;
    }

    // Next read/fill the rest of parameters
    //
    line = NULL;
    if (-1 != getline(&line, &len, pipe))
    {
        // Remove the last "\n"
        //
        line[strlen(line)-1] = 0x00;
    }

    pclose(pipe);
    pthread_mutex_unlock(&uci_mutex);

    return line;
}

static void _set_uci_parameter_value(char * parameter, uint8_t *value)
{
    FILE *pipe ;
    char command[200] = "";

    strcat(command,"uci set ");
    strcat(command,parameter);
    strcat(command, (char *)value);

    // Execute the UCI query command.
    //
    pthread_mutex_lock(&uci_mutex);
    pipe = popen(command, "r");

    if (!pipe)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] popen() returned with errno=%d (%s)\n", errno, strerror(errno));
        pthread_mutex_unlock(&uci_mutex);
        return;
    }

    pclose(pipe);
    pthread_mutex_unlock(&uci_mutex);

    return;
}

static void _get_wifi_connected_devices(char *interface_name, struct interfaceInfo *m)
{
    FILE    *pipe;
    char    *line;
    size_t   len;
    ssize_t  read;
    uint8_t    mac_addr[6];
    char     command[200];

    sprintf(command, "iw dev %s station dump | grep Station | cut -f2 -d' '",interface_name);

    // Execute the UCI query command.
    //
    pthread_mutex_lock(&uci_mutex);
    pipe = popen(command, "r");

    if (!pipe)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] popen() returned with errno=%d (%s)\n", errno, strerror(errno));
        pthread_mutex_unlock(&uci_mutex);
        return;
    }

    // Next read/fill the rest of parameters
    //
    line = NULL;
    m->neighbor_mac_addresses_nr = 0;
    m->neighbor_mac_addresses    = NULL;
    while (-1 != (read = getline(&line, &len, pipe)))
    {
        // Remove the last "\n"
        //
        line[strlen(line)-1] = 0x00;

        if (6 == sscanf(line, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac_addr[0], &mac_addr[1], &mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5]))
        {
             PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] %02x:%02x:%02x:%02x:%02x:%02x wifi device connected to %s\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5], interface_name);
             m->neighbor_mac_addresses = (uint8_t (*)[6])realloc(m->neighbor_mac_addresses, sizeof(uint8_t[6]) * m->neighbor_mac_addresses_nr + 1);
             memcpy(m->neighbor_mac_addresses[m->neighbor_mac_addresses_nr], mac_addr, 6);
             m->neighbor_mac_addresses_nr++;
        }
        else
        {
             PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] Invalid MAC address %s\n", line);
        }
    }

    if (m->neighbor_mac_addresses_nr == 0 )
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] No Wifi device connected \n");
    }

    pclose(pipe);
    pthread_mutex_unlock(&uci_mutex);

    return;
}


////////////////////////////////////////////////////////////////////////////////
// Internal API: to be used by other platform-specific files (functions
// declaration is found in "./platform_interfaces_openwrt_priv.h")
////////////////////////////////////////////////////////////////////////////////

uint8_t openwrt_get_interface_info(char *interface_name, struct interfaceInfo *m)
{
    // Check interface name
    //
    if (strstr(interface_name, "wlan") != NULL)
    {
        char  *line = NULL;
        char command[200];
        char *interface_id = interface_name + 4;

        // Find out if device is configured as AP or EP
        //
        sprintf(command, "wireless.@wifi-iface[%c].mode",*interface_id);

        line = _read_uci_parameter_value(command);
        if (line != NULL)
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM]   > UCI mode: %s\n", line);

            if (strstr(line, "ap") != NULL)
            {
                m->interface_type_data.ieee80211.role = IEEE80211_ROLE_AP;
            }
            else
            {
                m->interface_type_data.ieee80211.role = IEEE80211_ROLE_NON_AP_NON_PCP_STA;
            }
        }

        // Retrieve SSID information
        //
        sprintf(command, "wireless.@wifi-iface[%c].ssid",*interface_id);

        line = _read_uci_parameter_value(command);
        if (line != NULL)
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM]   > UCI SSID: %s\n", line);
            memcpy(m->interface_type_data.ieee80211.ssid, line, strlen(line)+1);
        }

        // Retrieve Network key information
        //
        sprintf(command, "wireless.@wifi-iface[%c].key",*interface_id);

        line = _read_uci_parameter_value(command);
        if (line != NULL)
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM]   > UCI key: %s\n", line);
            memcpy(m->interface_type_data.ieee80211.network_key, line, strlen(line)+1);
        }

        // Relases 'getline' resources
        free(line);

        // TODO: Add full support of WIFI parameters. For now, use static
        // values.
        //
        m->interface_type                                    = INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ;
        m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPAPSK     | IEEE80211_AUTH_MODE_WPA2PSK;
        m->interface_type_data.ieee80211.encryption_mode     = IEEE80211_ENCRYPTION_MODE_TKIP | IEEE80211_ENCRYPTION_MODE_AES;
        m->is_secured                                        = 1;

        m->interface_type_data.ieee80211.bssid[0] = 0x00;
        m->interface_type_data.ieee80211.bssid[1] = 0x00;
        m->interface_type_data.ieee80211.bssid[2] = 0x00;
        m->interface_type_data.ieee80211.bssid[3] = 0x00;
        m->interface_type_data.ieee80211.bssid[4] = 0x00;
        m->interface_type_data.ieee80211.bssid[5] = 0x00;


        //Retrieve list of connected devices
        //
        _get_wifi_connected_devices(interface_name,m);
    }
    else
    {
        m->interface_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;
        m->is_secured     = 1;
    }

    // TODO: Obtain the actual value for the following parameters
    //
    m->push_button_on_going        = 2; // "2" means "not supported"
    m->power_state                 = INTERFACE_POWER_STATE_ON;
    m->ipv4_nr                     = 0;
    m->ipv4                        = NULL;
    m->ipv6_nr                     = 0;
    m->ipv6                        = NULL;
    m->vendor_specific_elements_nr = 0;
    m->vendor_specific_elements    = NULL;

    return 1;
}

uint8_t openwrt_apply_80211_configuration(char *interface_name, uint8_t *ssid, uint8_t *network_key)
{
    _set_uci_parameter_value("wireless.@wifi-iface[1].ssid=",ssid);
    _set_uci_parameter_value("wireless.@wifi-iface[1].key=",network_key);
    _set_uci_parameter_value("wireless.@wifi-iface[1].network_key=",network_key);
    _set_uci_parameter_value("wireless.@wifi-iface[1].encryption=",(uint8_t *)"psk2");

    system("wifi reload");

    return 1;
}
