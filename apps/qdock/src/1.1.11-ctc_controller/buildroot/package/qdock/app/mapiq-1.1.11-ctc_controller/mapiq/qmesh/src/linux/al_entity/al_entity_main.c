/*
 *  Copyright (c) 2018-2020, Semiconductor Components Industries, LLC
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

#include <hlist.h>

#include <platform.h>
#include "../platform_interfaces_priv.h"            // addInterface
#include "../platform_interfaces_ghnspirit_priv.h"  // registerGhnSpiritInterfaceType
#include "../platform_interfaces_simulated_priv.h"  // registerSimulatedInterfaceType
#include "../platform_alme_server_priv.h"           // almeServerPortSet()
#include "../../al.h"                                  // start1905AL

#include <datamodel.h>
#include "../../al_datamodel.h"
#include "../../al_wsc.h"

#include <stdio.h>   // printf
#include <unistd.h>
#include <getopt.h>  // getopt
#include <stdlib.h>  // exit
#include <string.h>  // strtok
#define __STRICT_ANSI__
#ifdef Q_OPENWRT
#include "json-c/json.h"
#else
#include "json-c/json.h"
#endif
#ifdef Q_STEERING_LOGIC
#include "../../map_steering.h"
#endif

#ifdef OPENWRT
extern int  netlink_collect_local_infos(void);
#endif

////////////////////////////////////////////////////////////////////////////////
// Static (auxiliary) private functions, structures and macros
////////////////////////////////////////////////////////////////////////////////

// Port number where the ALME server will be listening to by default
//
#define DEFAULT_ALME_SERVER_PORT 8888

// This function receives a comma separated list of interface names (example:
// "eth0,eth1,wlan0") and, for each of them, calls "addInterface()" (example:
// addInterface("eth0") + addInterface("eth1") + addInterface("wlan0"))
//
static void _parseInterfacesList(const char *str)
{
    char *aux;
    char *interface_name;
    char *save_ptr;

    if (NULL == str)
    {
        return;
    }

    aux = strdup(str);

    interface_name = strtok_r(aux, ",", &save_ptr);
    if (NULL != interface_name)
    {
        addInterface(interface_name);

        while (NULL != (interface_name = strtok_r(NULL, ",", &save_ptr)))
        {
            addInterface(interface_name);
        }
    }

    free(aux);
    return;
}

struct mapConfig map_config;
struct mapapiConfig mapapi_config;

static void init_frame_subscribe(struct frame_suscribe_t *frame_suscribe)
{
    dlist_head_init(&frame_suscribe->rx_1905_suscribe);
}


static void _defaulConfigure()
{
    memset(&map_config, 0, sizeof(map_config));
    map_config.ap_metrics_intval = 5;
#ifndef Q_STEERING_LOGIC
    map_config.assoc_sta_intval = 5;
    map_config.unassoc_sta_intval = 5;
#else
    map_config.assoc_sta_intval = 1;
    map_config.unassoc_sta_intval = 1;
#endif
    map_config.support_agent_steering = 0;
    map_config.monitor_dwell = 50;
    map_config.rcpi_margin = 5;
    map_config.wait_roaming = 10;
    map_config.unassoc_sta_maxnums = 128;
    map_config.retries = 2;
    map_config.wait_ack = 1000;
    map_config.search_period = 5;
    map_config.autoconf_wait = 60;
    map_config.hide_backhaul_ssid = 1;
    map_config.dbg_level = 0;
    map_config.role = MAP_ROLE_AGENT;
    map_config.profile = 1;
    map_config.filter_1905packet = false;

    strcpy(map_config.wsc_data.manufacturer_name, "Quantenna");
    strcpy(map_config.wsc_data.device_name, "Reference Design");
    strcpy(map_config.wsc_data.model_name, "quantenna.mapiq");
    strcpy(map_config.wsc_data.model_number, "1.1");
    strcpy(map_config.wsc_data.serial_number, "002686000000");
    init_frame_subscribe(&map_config.frame_suscribe);
    memset(&mapapi_config, 0, sizeof(mapapi_config));

    map_config.topology_policy.APCapaQ_uponTopoR = true;
    map_config.topology_policy.ClientCapaQ_uponTopoR = false;
    map_config.topology_policy.APMetricsQ_uponTopoR = false;
    map_config.topology_policy.AssocedStaLinkQ_uponTopoR = false;

}


static void _parseWscInfoConfigure(struct json_object *jconfig)
{
    if (!jconfig)
        return;
	json_object_object_foreach(jconfig, key, obj)
    {
		if (!strcmp(key, "manufacturer_name"))
            strncpy(map_config.wsc_data.manufacturer_name, json_object_get_string(obj),
                    sizeof(map_config.wsc_data.manufacturer_name) - 1);
        else if (!strcmp(key, "device_name"))
            strncpy(map_config.wsc_data.device_name, json_object_get_string(obj),
                    sizeof(map_config.wsc_data.device_name) - 1);
        else if (!strcmp(key, "model_name"))
            strncpy(map_config.wsc_data.model_name, json_object_get_string(obj),
                    sizeof(map_config.wsc_data.model_name) - 1);
        else if (!strcmp(key, "model_number"))
            strncpy(map_config.wsc_data.model_number, json_object_get_string(obj),
                    sizeof(map_config.wsc_data.model_number) - 1);
        else if (!strcmp(key, "serial_number"))
            strncpy(map_config.wsc_data.serial_number, json_object_get_string(obj),
                    sizeof(map_config.wsc_data.serial_number) - 1);
    }
}

static void _parseConfigure(const char *file)
{
	struct json_object *jconfig;

    if (!file)
        return;

    jconfig = json_object_from_file(file);
    if (!jconfig)
        return;

	json_object_object_foreach(jconfig, key, obj)
    {
		if (!strcmp(key, "ap_metrics_intval"))
			map_config.ap_metrics_intval = json_object_get_int(obj);
		else if (!strcmp(key, "assoc_sta_intval"))
			map_config.assoc_sta_intval = json_object_get_int(obj);
		else if (!strcmp(key, "unassoc_sta_intval"))
			map_config.unassoc_sta_intval = json_object_get_int(obj);
		else if (!strcmp(key, "support_agent_steering"))
			map_config.support_agent_steering = json_object_get_int(obj);
		else if (!strcmp(key, "monitor_dwell"))
			map_config.monitor_dwell = json_object_get_int(obj);
		else if (!strcmp(key, "rcpi_margin"))
			map_config.rcpi_margin = json_object_get_int(obj);
		else if (!strcmp(key, "wait_roaming"))
			map_config.wait_roaming = json_object_get_int(obj);
		else if (!strcmp(key, "unassoc_sta_maxnums"))
			map_config.unassoc_sta_maxnums = json_object_get_int(obj);
		else if (!strcmp(key, "retries"))
			map_config.retries = json_object_get_int(obj);
		else if (!strcmp(key, "wait_ack"))
			map_config.wait_ack = json_object_get_int(obj);
		else if (!strcmp(key, "search_period"))
			map_config.search_period = json_object_get_int(obj);
		else if (!strcmp(key, "autoconf_wait"))
			map_config.autoconf_wait = json_object_get_int(obj);
		else if (!strcmp(key, "hide_backhaul_ssid"))
			map_config.hide_backhaul_ssid = json_object_get_int(obj);
		else if (!strcmp(key, "filter_1905packet"))
			map_config.filter_1905packet = json_object_get_int(obj);
		else if (!strcmp(key, "wsc_info"))
            _parseWscInfoConfigure(obj);
	}
};

static void _dumpConfigure(void)
{
    PLATFORM_PRINTF_DEBUG_DETAIL("MAP configuration:\n");
    PLATFORM_PRINTF_DEBUG_DETAIL("\trole:%s(profile: %d)\n", (map_config.role==MAP_ROLE_CONTROLLER ? "controller":"agent"), map_config.profile);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tap_metrics_intval:      %u\n", map_config.ap_metrics_intval);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tassoc_sta_intval:       %u\n", map_config.assoc_sta_intval);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tunassoc_sta_intval:     %u\n", map_config.unassoc_sta_intval);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tsupport_agent_steering: %u\n", map_config.support_agent_steering);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tmonitor_dwell:          %u\n", map_config.monitor_dwell);
    PLATFORM_PRINTF_DEBUG_DETAIL("\trcpi_margin:            %u\n", map_config.rcpi_margin);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tretries:                %u\n", map_config.retries);
    PLATFORM_PRINTF_DEBUG_DETAIL("\twait_ack:               %u\n", map_config.wait_ack);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tsearch_period:          %u\n", map_config.search_period);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tautoconf_wait:          %u\n", map_config.autoconf_wait);
    PLATFORM_PRINTF_DEBUG_DETAIL("\thide_backhaul_ssid:     %u\n", map_config.hide_backhaul_ssid);
    PLATFORM_PRINTF_DEBUG_DETAIL("\tWSC INFO:\n");
    PLATFORM_PRINTF_DEBUG_DETAIL("\t\tmanufacturer_name:    %s\n", map_config.wsc_data.manufacturer_name);
    PLATFORM_PRINTF_DEBUG_DETAIL("\t\tdevice_name:          %s\n", map_config.wsc_data.device_name);
    PLATFORM_PRINTF_DEBUG_DETAIL("\t\tmodel_name:           %s\n", map_config.wsc_data.model_name);
    PLATFORM_PRINTF_DEBUG_DETAIL("\t\tmodel_number:         %s\n", map_config.wsc_data.model_number);
    PLATFORM_PRINTF_DEBUG_DETAIL("\t\tserial_number:        %s\n", map_config.wsc_data.serial_number);
};

static void _printUsage(char *program_name)
{
    printf("AL entity (build %s)\n", _BUILD_NUMBER_);
    printf("\n");
    printf("Usage: %s -n <ni_interface> -m <al_mac_address> -i <interfaces_list> [-w] [-r <registrar_interface>] [-v] [-P <alme_port_number>] [-S/s] [-p <profile>] [--cfg2 <ini_file_for_2.4G] [--cfg5 <ini_file_for_5G]\n", program_name);
    printf("\n");
    printf("  ...where:\n");
    printf("       '<ni_interface>' is the internal interface between NPU and Q_WIFI devices\n");
    printf("       (ex: 'eth2'\n");
    printf("       To start al_entity on standalong: let ni_interface = null by default, don't use -n option\n");
    printf("       To start al_entity on NPU: set ni_interface to interface name by using -n option\n");
    printf("\n");
    printf("       '<al_mac_address>' is the AL MAC address that this AL entity will receive\n");
    printf("       (ex: '00:4f:21:03:ab:0c'\n");
    printf("\n");
    printf("       '<interfaces_list>' is a comma sepparated list of local interfaces that will be\n");
    printf("        managed by the AL entity (ex: 'eth0,eth1,wlan0')\n");
    printf("\n");
    printf("       '-w', if present, will instruct the AL entity to map the whole network (instead of\n");
    printf("       just its local neighbors)\n");
    printf("\n");
    printf("       '-r', if present, will tell the AL entity that '<registrar_interface>' is the name\n");
    printf("       of the local interface that will act as the *unique* wifi registrar in the whole\n");
    printf("       network.\n");
    printf("\n");
    printf("       '-c', map configure file\n");
    printf("\n");
    printf("       '-v', if present, will increase the verbosity level. Can be present more than once,\n");
    printf("       making the AL entity even more verbose each time.\n");
    printf("\n");
    printf("       '<alme_port_number>', is the port number where a TCP socket will be opened to receive\n");
    printf("       ALME messages. If this argument is not given, a default value of '8888' is used.\n");
    printf("\n");
    printf("       '-S', running as controller with local agent\n");
    printf("\n");
    printf("       '-s', running as controller only\n");
    printf("\n");
    printf("       '<profile>, specific EasyMesh profile level, default 1\n");
    printf("\n");
    printf("       '--cfg2' and '--cfg5' for using external ini file for 2.4g/5g BSS configuration\n");
    printf("\n");

    return;
}


////////////////////////////////////////////////////////////////////////////////
// External public functions
////////////////////////////////////////////////////////////////////////////////

static struct option long_options[] =
{
  {"cfg2", required_argument, 0, 2},
  {"cfg5", required_argument, 0, 5},
  {0, 0, 0, 0}
};
static int option_index = 0;

int main(int argc, char *argv[])
{
    mac_address al_mac_address = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t map_whole_network = 0;

    int   c;
    char *al_mac              = NULL;
    char *al_interfaces       = NULL;
    char *ni_interface        = NULL;
    int  alme_port_number     = 0;
    char *registrar_interface = NULL;
    const char *config_file   = NULL;

    int verbosity_counter = 1; // Only ERROR and WARNING messages

    // registerGhnSpiritInterfaceType();
    // registerSimulatedInterfaceType();

    _defaulConfigure();

    while ((c = getopt_long(argc, argv, "n:m:i:wr:vh:p:c:Ss", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'n':
            {
                // npu to qtna device interface: 'eth2'
                //
                ni_interface = optarg;
                break;
            }
            case 'm':
            {
                // AL MAC address in "xx:xx:..:xx" format
                //
                al_mac = optarg;
                break;
            }
            case 'i':
            {
                // Comma separated list of interfaces: 'eth0,eth1,wlan0'
                //
                al_interfaces = optarg;
                break;
            }
            case 'w':
            {
                // If set to '1', the AL entity will not only query its direct
                // neighbors, but also its neighbors's neighbors and so on...
                // taking much more memory but obtaining a whole network map.
                //
                map_whole_network = 1;
                break;
            }
            case 'r':
            {
                // This is the interface that acts as Wifi registrar in the
                // network.
                // Remember that only one interface in the whole network should
                // act as a registrar.
                //
                registrar_interface = optarg;
                break;
            }
            case 'v':
            {
                // Each time this flag appears, the verbosity counter is
                // incremented.
                //
                verbosity_counter++;
                break;
            }
            case 'P':
            {
                // Alme server port number
                //
                alme_port_number = atoi(optarg);
                break;
            }
            case 'c':
            {
                config_file = optarg;
                break;
            }
            case 'S':
            {
                map_config.role = MAP_ROLE_CONTROLLER | MAP_ROLE_AGENT;
                break;
            }
            case 's':
            {
                map_config.role = MAP_ROLE_CONTROLLER;
                break;
            }
            case 'p':
            {
                map_config.profile = atoi(optarg);
                break;
            }
            case 2:
            {
                map_config.ini2 = optarg;
                break;
            }
            case 5:
            {
                map_config.ini5 = optarg;
                break;
            }
            case 'h':
            {
                _printUsage(argv[0]);
                exit(0);
            }

        }
    }

#ifdef QDOCK
    if (NULL == al_mac)
#else
    if (NULL == al_mac || NULL == al_interfaces)
#endif
    {
        _printUsage(argv[0]);
        exit(1);
    }

    if (0 == alme_port_number)
    {
        alme_port_number = DEFAULT_ALME_SERVER_PORT;
    }

    PLATFORM_PRINTF_DEBUG_SET_VERBOSITY_LEVEL(verbosity_counter);

    asciiToMac(al_mac, al_mac_address);

    wscGenUUID(al_mac_address, map_config.wsc_data.uuid);
    _parseConfigure(config_file);
    _dumpConfigure();

    _parseInterfacesList(al_interfaces);

    if (ni_interface)
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("ni_interface = %s\n", ni_interface);
        strncpy(ni_interface_name, ni_interface, IFNAMSIZ-1);
    }

    almeServerPortSet(alme_port_number);

    // Initialize platform-specific code
    //
    if (0 == PLATFORM_INIT())
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Failed to initialize platform\n");
        return AL_ERROR_OS;
    }

    // Insert the provided AL MAC address into the database
    //
    DMinit();
    DMalMacSet(al_mac_address);
    DMmapWholeNetworkSet(map_whole_network);
    PLATFORM_PRINTF_DEBUG_DETAIL("Starting AL entity (AL MAC = %02x:%02x:%02x:%02x:%02x:%02x). Map whole network = %d...\n",
                                al_mac_address[0],
                                al_mac_address[1],
                                al_mac_address[2],
                                al_mac_address[3],
                                al_mac_address[4],
                                al_mac_address[5],
                                map_whole_network);

#ifdef OPENWRT
    // Collect all the informations about local radios throught netlink
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Retrieving list of local radios throught netlink...\n");
    if (0 > netlink_collect_local_infos())
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Failed to collect radios from netlink\n");
        return AL_ERROR_OS;
    }
#endif

    // Collect interfaces
    PLATFORM_PRINTF_DEBUG_DETAIL("Retrieving list of local interfaces...\n");
    createLocalInterfaces();

    if (map_config.role & MAP_ROLE_CONTROLLER)
    {
        registrar.d = local_device;
        registrar.is_map = true;
        local_device->is_map_controller = true;
        map_config.topology_policy.ClientCapaQ_uponTopoR = true;
    }
    else if (map_config.role == MAP_ROLE_AGENT)
    {
        local_device->is_map_agent = true;
    }

    local_device->profile = map_config.profile;

    // If an interface is the designated 1905 network registrar
    // interface, save its MAC address to the database
    //
    if (NULL != registrar_interface)
    {
        struct interface *interface;
        struct interfaceWifi *interface_wifi;

        interface = findLocalInterface(registrar_interface);

        if (interface == NULL)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Could not find registrar interface %s\n", registrar_interface);
        }
        else if (interface->type != interface_type_wifi)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Registrar interface %s is not a Wifi interface\n", registrar_interface);
        }
        else
        {
            struct interfaceInfo *x;

            interface_wifi = container_of(interface, struct interfaceWifi, i);
            x = PLATFORM_GET_1905_INTERFACE_INFO(interface->name);
            if (!x)
                return AL_ERROR_OS;

            registrar.d = local_device;
            /* For now, it is always a MAP Controller. */
            registrar.is_map = true;

            /* Copy interface info into WSC info.
             * @todo Support multiple bands.
             */
            struct wscRegistrarInfo *wsc_info = zmemalloc(sizeof(struct wscRegistrarInfo));
            memcpy(&wsc_info->bss_info, &interface_wifi->bssInfo, sizeof(wsc_info->bss_info));
            strncpy(wsc_info->device_data.device_name, map_config.wsc_data.device_name, sizeof(wsc_info->device_data.device_name) - 1);
            strncpy(wsc_info->device_data.manufacturer_name, map_config.wsc_data.manufacturer_name, sizeof(wsc_info->device_data.manufacturer_name) - 1);
            strncpy(wsc_info->device_data.model_name, map_config.wsc_data.model_name, sizeof(wsc_info->device_data.model_name) - 1);
            strncpy(wsc_info->device_data.model_number, map_config.wsc_data.model_number, sizeof(wsc_info->device_data.model_number) - 1);
            strncpy(wsc_info->device_data.serial_number, map_config.wsc_data.serial_number, sizeof(wsc_info->device_data.serial_number) - 1);
            /* @todo support UUID; for now its 0. */
            switch(x->interface_type)
            {
                case INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ:
                case INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ:
                case INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ:
                    wsc_info->rf_bands = WPS_RF_24GHZ;
                    break;

                case INTERFACE_TYPE_IEEE_802_11A_5_GHZ:
                case INTERFACE_TYPE_IEEE_802_11N_5_GHZ:
                case INTERFACE_TYPE_IEEE_802_11AC_5_GHZ:
                case INTERFACE_TYPE_IEEE_802_11AX:
                    wsc_info->rf_bands = WPS_RF_50GHZ;
                    break;

                case INTERFACE_TYPE_IEEE_802_11AD_60_GHZ:
                    wsc_info->rf_bands = WPS_RF_60GHZ;
                    break;

                case INTERFACE_TYPE_IEEE_802_11AF_GHZ:
                    PLATFORM_PRINTF_DEBUG_ERROR("Interface %s is 802.11af which is not supported by WSC!\n",x->name);

                    free_1905_INTERFACE_INFO(x);
                    return AL_ERROR_INTERFACE_ERROR;

                default:
                    PLATFORM_PRINTF_DEBUG_ERROR("Interface %s is not a 802.11 interface and thus cannot act as a registrar!\n",x->name);

                    free(wsc_info);
                    free_1905_INTERFACE_INFO(x);
                    return AL_ERROR_INTERFACE_ERROR;

            }

            registrarAddWsc(wsc_info);
            free_1905_INTERFACE_INFO(x);
        }
    }

#ifdef Q_STEERING_LOGIC
    defaultQSteeringConfig();
    if (map_steering_config.steering_enabled)
        startQSteering();
#endif

    start1905AL();

    return 0;
}
