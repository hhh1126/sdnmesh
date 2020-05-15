/*
 *  Copyright (c) 2019, Semiconductor Components Industries, LLC
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
 * @brief ubus map network object implementation
 *
 */

#include "qdock_map_api.h"
#include "al_ubus_server.h"

#include "platform.h"
#include "datamodel.h"
#include "al_utils.h"
#include "al_datamodel.h"

void blobmsg_add_mac_fmt(struct blob_buf *buf, const char *name, uint8_t *mac, int mac_fmt)
{
    char mac_string[18];
    if(mac_fmt){
        sprintf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        blobmsg_add_string(buf, name, mac_string);
    }else
        blobmsg_add_mac(buf,name, mac);
}


#define rcpi_to_rssi(rcpi)   (((rcpi) < 220) ? ((int)((rcpi) / 2) - 110) : 0)


typedef struct devlist {

#define INVALID_NODE  0
#define VALID_NODE  1
#define ALL_DEVICE 0
#define VALID_DEVICE 1

    int flag ;
    struct alDevice *dev;
    struct devlist *next;
} ALlist;


static ALlist *list_head = NULL;
static void aldev_list_add(ALlist **head, ALlist *Node, int head_flag)
{

    ALlist *temp;
    if(NULL == *head)
    {
        *head = Node;
        (*head)->next = NULL;
    }
    else if(head_flag)
    {
        temp = *head;
        *head = Node;
        Node->next = temp;
    }else{
        temp = *head;
        while(temp)
        {
            if(NULL == temp->next)
            {
                temp->next = Node;
                Node->next = NULL;
                return ;
            }
            temp = temp->next;
        }
    }
}

static void list_free(ALlist **head)
{
    ALlist *temp;
    ALlist *free_node;
    if(NULL != *head)
    {
        temp = *head;
        while(temp)
        {
            free_node= temp;
            temp = temp->next;
            if(free_node)
            {
                free(free_node);
            }
        }
    }
    *head = NULL;
}

static int link_aldev_list()
{
    struct alDevice *dev;
    ALlist *listNode = NULL;
    list_head = NULL;
    dlist_for_each(dev, network, l)
    {
        listNode = malloc(sizeof(ALlist));
        listNode->dev = dev;
        listNode->flag = VALID_NODE;
        aldev_list_add(&list_head, listNode, dev->is_map_controller?1:0 );
    }
    return 0;
}

int is_dev_connect(struct alDevice *dev, struct staInfo *sta)
{
    struct interface *intf;
    int ret = -1;
    dlist_for_each(intf, dev->interfaces, l)
    {
        if(memcmp(intf->addr,sta->mac, 6) == 0)
        {
            ret = 0;
            break ;
        }
    }
    return ret;
}

struct alDevice *
have_sub_device(struct staInfo *sta, ALlist * list_head, int flag)
{
    ALlist *curr_dev = list_head;
    while(curr_dev)
    {
        if(flag && (curr_dev-> flag == INVALID_NODE))
        {
            curr_dev = curr_dev->next;
            continue;
        }
        if(! is_dev_connect(curr_dev->dev, sta))
        {
            return curr_dev->dev;
        }
        curr_dev = curr_dev->next;
    }
    return NULL;
}

static int
remove_dev_from_list(struct alDevice *dev, ALlist * list_head)
{
    ALlist *temp = list_head;
    int ret = -1;
    while(temp)
    {
        if(temp->dev == dev)
        {
            temp->flag = INVALID_NODE;
            ret = 0;
            break ;
        }
        temp = temp->next;
    }
    return ret ;
}


static int radio_5g_check(struct radio *radio)
{
    uint32_t i;
    int ret = 0;
    if(!radio)
        return 1;

    for (i = 0; i < radio->opclass_nums; i++)
    {
        if (radio->opclasses[i].opclass > 114 )
        {
            ret = 1;
            break ;
        } else if(radio->opclasses[i].opclass > 80){
            ret = 0;
            break ;
        }
    }

    return ret;
}


static void fill_assoced_station_info(struct staInfo *sta, struct radio *radio)
{
    void * sta_table = blobmsg_open_table(&b, NULL);
    int radio_type = radio_5g_check(radio);

    blobmsg_add_string(&b, "name", "");
    blobmsg_add_string(&b, "role", "client");
    blobmsg_add_string(&b, "ip", "");
    blobmsg_add_mac_fmt(&b, "mac", sta->mac, 1);

    blobmsg_add_string(&b, "link", radio_type ? "5G":"2.4G");
    blobmsg_add_u32(&b, "rssi", rcpi_to_rssi(sta->link_metrics.rcpi_ul));
    blobmsg_add_u32(&b, "phyrate", sta->link_metrics.rate_dl);
    blobmsg_close_table(&b, sta_table );

}

static void
fill_controller_agent_info(struct alDevice *dev, struct staInfo *sta, struct radio *radio)
{
    int radio_type = radio_5g_check(radio);

    blobmsg_add_string(&b, "name", "");

    if (dev->is_map_controller)
        blobmsg_add_string(&b, "role", "controller");
    else if(dev->is_map_agent)
        blobmsg_add_string(&b, "role", "agent");
    else
        blobmsg_add_string(&b, "role", "unconfigured");

    blobmsg_add_string(&b, "ip", "");
    blobmsg_add_mac_fmt(&b, "mac", dev->al_mac_addr, 1);
    if(dev->is_map_agent && sta && radio)
    {
        blobmsg_add_string(&b, "link", radio_type ? "5G":"2.4G");
        blobmsg_add_u32(&b, "rssi", rcpi_to_rssi(sta->link_metrics.rcpi_ul));
        blobmsg_add_u32(&b, "phyrate", sta->link_metrics.rate_dl);
    }

}

int func_add_dev(struct alDevice *dev, ALlist * list_head, struct staInfo *substa,  struct radio *subradio)
{
    void * sec_layer_table = blobmsg_open_table(&b, NULL);
    struct radio *radio;
    void *client_list_new = NULL;

    remove_dev_from_list(dev, list_head);
    fill_controller_agent_info(dev, substa, subradio);

    dlist_for_each(radio, dev->radios, l)
    {
        uint32_t i;
        for (i = 0; i < radio->configured_bsses.length; i++)
        {
            struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
            struct staInfo *sta;
            dlist_for_each(sta, ifw->clients, l)
            {
                struct alDevice * sub_dev;
                sub_dev = have_sub_device(sta, list_head, ALL_DEVICE);
                if(client_list_new == NULL && sub_dev == NULL)
                    client_list_new = blobmsg_open_array(&b, "client");

                if(sub_dev)
                {
                    sub_dev = have_sub_device(sta, list_head, VALID_DEVICE) ;
                    if (sta->bSTA || sub_dev )
                    {
                        if(sub_dev)
                        {
                            if(client_list_new == NULL)
                                client_list_new = blobmsg_open_array(&b, "client");
                            func_add_dev(sub_dev, list_head, sta, radio);
                        }
                    }
                }else{
                    fill_assoced_station_info(sta, radio);
                }
            }
        }
    }

    if(client_list_new)
        blobmsg_close_array(&b, client_list_new);

    blobmsg_close_table(&b, sec_layer_table );

    return 0;
}

static void fill_topology_map(ALlist *list_head)
{
    ALlist *curr_dev = list_head;
    void *node_list = NULL;
    char local_role[] ={"Unconfigured"};

    if (local_device->is_map_agent)
    {
        strcpy(local_role,"agent");
    }

    if(local_device-> is_map_controller)
    {
        strcpy(local_role,"controller");
    }

    blobmsg_add_string(&b, "observer", local_role);
    node_list = blobmsg_open_array(&b, "node");

    while(curr_dev)
    {
        if(curr_dev-> flag == INVALID_NODE)
        {
            curr_dev = curr_dev->next;
            continue;
        }
        func_add_dev(curr_dev->dev, list_head, NULL, NULL);
        curr_dev = curr_dev->next;
    }

    blobmsg_close_array(&b, node_list);
}

static void fill_controller_mac()
{
    struct alDevice *dev = NULL;
    char ctr_mac[32] = {'\0'};

    dlist_for_each(dev, network, l) {
        if (dev && dev->is_map_controller) {
            snprintf(ctr_mac, sizeof(ctr_mac), MACFMT, MACARG(dev->al_mac_addr));
            break;
        }
    }

    blobmsg_add_string(&b, "controller_mac", ctr_mac);
}

static void fill_device_capabilities(struct alDevice *dev)
{
    void *table = blobmsg_open_table(&b, MAPAPI_DEVICE_ATTR_CAPABILITIES_NAME);
    uint32_t monitor_onchan = 0;
    uint32_t monitor_offchan = 0;
    uint32_t self_steering = 0;
    struct radio *radio;

    dlist_for_each(radio, dev->radios, l)
    {
        monitor_onchan |= radio->monitor_onchan;
        monitor_offchan |= radio->monitor_offchan;
        self_steering |= radio->self_steering;
    }
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_MON_ONCHAN_NAME, monitor_onchan);
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_MON_OFFCHAN_NAME, monitor_offchan);
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_SELF_STEERING_NAME, self_steering);

    // TODO max_VID . uint8. Only if .device[al_address].map_profile > 1.
    // TODO stats . Only if .device[al_address].map_profile > 1.

    blobmsg_close_table(&b, table);
}

static void fill_device_radio(struct radio *radio, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac_fmt(&b, MAPAPI_RADIO_ATTR_ID_NAME, radio->uid,mac_fmt);
    blobmsg_close_table(&b, table);
}

static void fill_device_station(struct staInfo *sta, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);
    if (!sta->bSTA)
        blobmsg_add_mac_fmt(&b, MAPAPI_STATION_ATTR_MAC_NAME, sta->mac, mac_fmt);
    blobmsg_close_table(&b, table);
}

static void fill_device_basic(struct alDevice *dev, int mac_fmt)
{
    blobmsg_add_mac_fmt(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr,mac_fmt);
    blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_PROFILE_NAME, dev->profile);

    if (dev->is_map_controller)
        blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_ROLE_NAME, MAPAPI_1905_ROLE_REGISTRAR);
    else
        blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_ROLE_NAME, MAPAPI_1905_ROLE_RESERVED);

    if (dev->is_map_controller || dev->is_map_agent)
    {
        void *services_list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_SUPPORTED_SERVICES_NAME);
        void *service_table;
        if (dev->is_map_controller)
        {
            service_table = blobmsg_open_table(&b, NULL);
            blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_SERVICE_NAME, 0);
            blobmsg_close_table(&b, service_table);
        }
        if (dev->is_map_agent)
        {
            service_table = blobmsg_open_table(&b, NULL);
            blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_SERVICE_NAME, 1);
            blobmsg_close_table(&b, service_table);
        }
        blobmsg_close_array(&b, services_list);
    }
}

static void fill_device_last_topology_response(struct alDevice *dev)
{
    blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_LAST_TOPOLOGY_RESPONSE_TS_NAME, dev->last_topo_resp_ts);
}

static void fill_device_non1905_neighbors(struct alDevice *dev, int mac_fmt)
{
    uint8_t i;
    void *intf_list;
    uint8_t *non1905_neighbors_nr;
    struct non1905NeighborDeviceListTLV ***non1905_neighbors;
    non1905_neighbors = DMnon1905neighborGet(dev->al_mac_addr, &non1905_neighbors_nr);
    if (!non1905_neighbors || (*non1905_neighbors_nr == 0))
        return;

    intf_list = blobmsg_open_array(&b, MAPAPI_INTERFACE_ATTR_NON_1905_NEIGHBORS_NAME);
    for(i = 0; i < *non1905_neighbors_nr; i++)
    {
        uint8_t j;
        void *intf_table;
        void *neigh_list;
        intf_table = blobmsg_open_table(&b, NULL);
        blobmsg_add_mac_fmt(&b, MAPAPI_INTERFACE_ATTR_PEER_IF_ADDRESS_NAME, (*non1905_neighbors)[i]->local_mac_address,mac_fmt);
        neigh_list = blobmsg_open_array(&b, MAPAPI_INTERFACE_ATTR_NEIGHBORS_NAME);
        for (j = 0; j < (*non1905_neighbors)[i]->non_1905_neighbors_nr; j++)
        {
            void *neigh_table = blobmsg_open_table(&b, NULL);
            blobmsg_add_mac_fmt(&b, MAPAPI_INTERFACE_ATTR_NEIGHBOR_ADDR_NAME, (*non1905_neighbors)[i]->non_1905_neighbors[j].mac_address,mac_fmt);
            blobmsg_close_table(&b, neigh_table);
        }
        blobmsg_close_array(&b, neigh_list);
        blobmsg_close_table(&b, intf_table);
    }
    blobmsg_close_array(&b, intf_list);
}

static void fill_device_interface(struct alDevice *dev, struct interface *intf, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);

    blobmsg_add_mac_fmt(&b, MAPAPI_INTERFACE_ATTR_MAC_ADDR_NAME, intf->addr,mac_fmt);
    blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_MEDIA_TYPE_NAME, intf->media_type);
    blobmsg_add_binary(&b, MAPAPI_INTERFACE_ATTR_MEDIA_INFO_NAME, intf->media_specific_info, intf->media_specific_info_length);
    if (intf->type == interface_type_ethernet)
    {
        blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_IF_TYPE_NAME, MAPAPI_INTERFACE_TYPE_ETH);
    }
    else if (intf->type == interface_type_wifi)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (ifw->role == interface_wifi_role_ap)
            blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_IF_TYPE_NAME, MAPAPI_INTERFACE_TYPE_BSS);
        else if (ifw->role == interface_wifi_role_sta)
            blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_IF_TYPE_NAME, MAPAPI_INTERFACE_TYPE_STA);
        if (ifw->radio)
            blobmsg_add_mac_fmt(&b, MAPAPI_BSS_ATTR_RADIO_NAME, ifw->radio->uid, mac_fmt);
    }

    fill_device_non1905_neighbors(dev, mac_fmt);

    blobmsg_close_table(&b, table);
}

static void fill_device_interfaces(struct alDevice *dev, int mac_fmt)
{
    struct interface *intf;
    void *list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_INTERFACES_NAME);
    dlist_for_each(intf, dev->interfaces, l)
    {
        fill_device_interface(dev, intf, mac_fmt);
    }
    blobmsg_close_array(&b, list);
}

static void fill_device_1905_neighbors(struct alDevice *dev, int mac_fmt)
{
    uint8_t i;
    void *intf_list;
    uint8_t *neighbors_nr;
    struct neighborDeviceListTLV ***neighbors;
    neighbors = DM1905neighborGet(dev->al_mac_addr, &neighbors_nr);
    if (!neighbors || (*neighbors_nr == 0))
        return;

    intf_list = blobmsg_open_array(&b, MAPAPI_INTERFACE_ATTR_1905_NEIGHBORS_NAME);
    for(i = 0; i < *neighbors_nr; i++)
    {
        uint8_t j;
        void *neigh_list;
        blobmsg_add_mac_fmt(&b, MAPAPI_INTERFACE_ATTR_PEER_IF_ADDRESS_NAME, (*neighbors)[i]->local_mac_address, mac_fmt);
        neigh_list = blobmsg_open_array(&b, MAPAPI_INTERFACE_ATTR_NEIGHBORS_NAME);
        for (j = 0; j < (*neighbors)[i]->neighbors_nr; j++)
        {
            void *neigh_table = blobmsg_open_table(&b, NULL);
            blobmsg_add_mac_fmt(&b, MAPAPI_INTERFACE_ATTR_NEIGHBOR_ADDR_NAME, (*neighbors)[i]->neighbors[j].mac_address, mac_fmt);
            blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_IS_BRIDGE_NAME, (*neighbors)[i]->neighbors[j].bridge_flag);
            blobmsg_close_table(&b, neigh_table);
        }
        blobmsg_close_array(&b, neigh_list);
    }
    blobmsg_close_array(&b, intf_list);
    // TODO other 1905 neighbor infos like stats
}

static void fill_device(struct alDevice *dev, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);

    fill_device_basic(dev, mac_fmt);

    // TODO [SteeringOpportunity]: only present if qdock.mapiq.config.MAPController.Enabled is true
    // TODO opportunity_expiration : timestamp
    // TODO country_code: char[2]

    fill_device_capabilities(dev);

    {
        void *list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_RADIOS_NAME);
        struct radio *radio;
        dlist_for_each(radio, dev->radios, l)
            fill_device_radio(radio,mac_fmt);
        blobmsg_close_array(&b, list);
    }

    {
        void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_STATIONS_NAME);
        struct radio *radio;
        dlist_for_each(radio, dev->radios, l)
        {
            uint32_t i;
            for (i = 0; i < radio->configured_bsses.length; i++)
            {
                struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
                struct staInfo *sta;
                dlist_for_each(sta, ifw->clients, l)
                {
                    fill_device_station(sta, mac_fmt);
                }
            }
        }
        blobmsg_close_array(&b, list);
    }

    blobmsg_close_table(&b, table);
}

static void fill_unassoc_station_stas(struct radioUnassocSta *sta)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_STAS_NAME);

    blobmsg_add_mac(&b, MAPAPI_UNASSOC_STATION_ATTR_MAC_NAME, sta->mac);
    blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_CHANNEL_NAME, sta->channel);
    blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_OPCLASS_NAME, sta->opclass);
    blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_LAST_UPDATED_NAME, sta->last_ts);
    blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_RCPI_NAME, sta->rcpi);

    blobmsg_close_table(&b, table);
}

static void fill_unassoc_station_assoc_with(struct radioUnassocSta *sta)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_ASSOC_WITH_NAME);
    struct interfaceWifi *ifw = NULL;
    struct alDevice *dev = NULL;

    if (findWifiClient(sta->mac, &ifw, &dev))
    {
        if (ifw)
            blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
        if (dev)
        {
            blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr);
            blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_PROFILE_NAME, dev->profile);
        }
    }

    blobmsg_close_table(&b, table);
}

static void fill_unassoc_station(struct radioUnassocSta *sta)
{
    void *table = blobmsg_open_table(&b, NULL);
    // TODO may no need to organize as opclasses--chans--stas
    fill_unassoc_station_stas(sta);
    fill_unassoc_station_assoc_with(sta);
    blobmsg_close_table(&b, table);
}

static void fill_device_unassoc(struct alDevice *dev, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);

    blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr);

    {
        void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_UNASSOC_STATIONS_NAME);
        struct radio *radio;
        dlist_for_each(radio, dev->radios, l)
        {
            struct radioUnassocSta *sta;
            dlist_for_each(sta, radio->unassocStaHead, l)
            {
                fill_unassoc_station(sta);
            }
        }
        blobmsg_close_array(&b, list);
    }

    blobmsg_close_table(&b, table);
}

static void fill_assoced_station_link_metrics(struct staInfo *sta)
{
    void *link_table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_LINK_METRIC_NAME);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_AGE_NAME, sta->link_metrics.last_ts);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_DLRATE_NAME, sta->link_metrics.rate_dl);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_ULRATE_NAME, sta->link_metrics.rate_ul);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_RCPI_NAME, sta->link_metrics.rcpi_ul);
    blobmsg_close_table(&b, link_table);
}

static void fill_assoced_station_stas(struct staInfo *sta, struct radio *radio, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_STAS_NAME);

    blobmsg_add_mac_fmt(&b, MAPAPI_STATION_ATTR_MAC_NAME, sta->mac, mac_fmt);
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_CHANNEL_NAME, radio->chan);
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_OPCLASS_NAME, radio->opclass);
    fill_assoced_station_link_metrics(sta);
    blobmsg_close_table(&b, table);
}

static void fill_assoced_station_seen_by_devices(struct staInfo *sta, int mac_fmt)
{
    void *list = blobmsg_open_array(&b, MAPAPI_STATION_ATTR_SEEN_BY_DEVICES_NAME);
    struct alDevice *dev;

    dlist_for_each(dev, network, l)
    {
        struct radioUnassocSta *unassoc_sta = NULL;

        if (dev == local_device)
            continue;

        unassoc_sta = findUnassocClientByDevice(sta->mac, dev);
        if (unassoc_sta)
        {
            void *table = blobmsg_open_table(&b, NULL);
            blobmsg_add_mac_fmt(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr, mac_fmt);
            blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_CHANNEL_NAME, unassoc_sta->channel);
            blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_OPCLASS_NAME, unassoc_sta->opclass);
            blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_LAST_UPDATED_NAME, unassoc_sta->last_ts);
            blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_RCPI_NAME, unassoc_sta->rcpi);
            // TODO bssid which this sta has been associated with
            blobmsg_close_table(&b, table);
        }
    }

    blobmsg_close_array(&b, list);
}

static void fill_assoced_station(struct staInfo *sta, struct radio *radio, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);
    // TODO may no need to organize as opclasses--chans--stas
    fill_assoced_station_stas(sta, radio, mac_fmt);
    fill_assoced_station_seen_by_devices(sta, mac_fmt);
    blobmsg_close_table(&b, table);
}

static void fill_device_nearby(struct alDevice *dev, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);


    blobmsg_add_mac_fmt(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr, mac_fmt);


    {
        void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_STATIONS_NAME);
        struct radio *radio;
        dlist_for_each(radio, dev->radios, l)
        {
            uint32_t i;
            for (i = 0; i < radio->configured_bsses.length; i++)
            {
                struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
                struct staInfo *sta;
                dlist_for_each(sta, ifw->clients, l)
                {
                    if (!sta->bSTA)
                        fill_assoced_station(sta, radio, mac_fmt);
                }
            }
        }
        blobmsg_close_array(&b, list);
    }

    blobmsg_close_table(&b, table);
}

static void fill_devices(dlist_head *devices, void (*fill_func)(struct alDevice *, int mac_fmt), int mac_fmt)
{
    void *list = blobmsg_open_array(&b, MAPAPI_NETWORK_ATTR_DEVICES_NAME);
    struct macAddressItem *alid;

    if (dlist_count(devices))
    {
        dlist_for_each(alid, *devices, l)
        {
            struct alDevice *dev = alDeviceFind(alid->mac);
            if (dev)
                fill_func(dev, mac_fmt);
        }
    }
    else
    {
        struct alDevice *dev;
        dlist_for_each(dev, network, l)
        {
            fill_func(dev, mac_fmt);
        }
    }
    blobmsg_close_array(&b, list);
}

static void fill_topology_device(struct alDevice *dev, int mac_fmt)
{
    void *table = blobmsg_open_table(&b, NULL);

    fill_device_basic(dev, mac_fmt);
    fill_device_last_topology_response(dev);
    fill_device_interfaces(dev, mac_fmt);
    fill_device_1905_neighbors(dev, mac_fmt);

    blobmsg_close_table(&b, table);
}

static void fill_topology(int mac_fmt)
{
    void *list = blobmsg_open_array(&b, MAPAPI_NETWORK_ATTR_DEVICES_NAME);
    struct alDevice *dev;
    dlist_for_each(dev, network, l)
    {
        fill_topology_device(dev, mac_fmt);
    }
    blobmsg_close_array(&b, list);
}

static void fill_opclass_non_operable_channels(struct radioOpclass *opclass)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPAPI_OPCLASS_ATTR_NON_OPERABLE_CHANNELS_NAME);
    for (i = 0; i < opclass->channel_nums; i++)
    {
        if (opclass->channels[i].disabled)
        {
            void *table = blobmsg_open_table(&b, NULL);
            blobmsg_add_u32(&b, MAPAPI_CHANNEL_ATTR_ID_NAME, opclass->channels[i].id);
            blobmsg_close_table(&b, table);
        }
    }
    blobmsg_close_array(&b, list);
}

static void fill_radio_opclass(struct radioOpclass *opclass)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_ID_NAME, opclass->opclass);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_BW_NAME, opclass->bw);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_MAXPOWER_NAME, opclass->max_txpower);
    fill_opclass_non_operable_channels(opclass);
    blobmsg_close_table(&b, table);
}

static void fill_radio_opclasses(struct radio *radio)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_OPCLASSES_NAME);

    for (i = 0; i < radio->opclass_nums; i++)
        fill_radio_opclass(&radio->opclasses[i]);

    blobmsg_close_array(&b, list);
}

static void fill_radio_current_opclass(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_OPCLASS_NAME);
    uint8_t i;

    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_ID_NAME, radio->opclass);
    for (i = 0; i < radio->opclass_nums; i++)
    {
        struct radioOpclass *opclass = &radio->opclasses[i];
        if (opclass->opclass == radio->opclass)
        {
            blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_BW_NAME, opclass->bw);
            break;
        }
    }

    blobmsg_close_table(&b, table);
}

static void fill_opclass_channels(struct radioOpclass *opclass)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPAPI_OPCLASS_ATTR_CHANNELS_NAME);
    for (i = 0; i < opclass->channel_nums; i++)
    {
        void *table = blobmsg_open_table(&b, NULL);
        blobmsg_add_u32(&b, MAPAPI_CHANNEL_ATTR_ID_NAME, opclass->channels[i].id);
        blobmsg_add_u32(&b, MAPAPI_CHANNEL_ATTR_PREF_NAME, opclass->channels[i].pref);
        blobmsg_add_u32(&b, MAPAPI_CHANNEL_ATTR_REASON_NAME, opclass->channels[i].reason);
        blobmsg_add_u32(&b, MAPAPI_CHANNEL_ATTR_MIN_SEP_NAME, opclass->channels[i].min_sep);
        // TODO dfs
        blobmsg_close_table(&b, table);
    }
    blobmsg_close_array(&b, list);
}

static void fill_radio_opclass_status(struct radioOpclass *opclass)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_ID_NAME, opclass->opclass);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_BW_NAME, opclass->bw);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_MAXPOWER_NAME, opclass->max_txpower);
    fill_opclass_channels(opclass);
    blobmsg_close_table(&b, table);
}

static void fill_radio_opclasses_status(struct radio *radio)
{
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_OPCLASSES_STATUS_NAME);
    uint8_t i;

    for (i = 0; i < radio->opclass_nums; i++)
        fill_radio_opclass_status(&radio->opclasses[i]);

    blobmsg_close_array(&b, list);
}

static void fill_radio_operations(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_OPERATIONS_NAME);

    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_MAXBSSES_NAME, radio->maxBSS);
    fill_radio_opclasses(radio);
    // TODO supported: bitmask {HT, VHT, HE} Determined which objects below exists
    blobmsg_add_binary(&b, MAPAPI_RADIO_ATTR_HTCAPA_NAME, (uint8_t *)(&radio->ht_capa), sizeof(struct radioHtcap));
    blobmsg_add_binary(&b, MAPAPI_RADIO_ATTR_VHTCAPA_NAME, (uint8_t *)(&radio->vht_capa), sizeof(struct radioVhtcap));
    blobmsg_add_binary(&b, MAPAPI_RADIO_ATTR_HECAPA_NAME, (uint8_t *)(&radio->he_capa), sizeof(struct radioHecap));

    blobmsg_close_table(&b, table);
}

static void fill_radio_capabilities(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_CAPABILITIES_NAME);
    // TODO bSTA : bool. Indicates whether the radio can be a backhaul STA
    // TODO bSTA_address : mac address (may be null)
    fill_radio_operations(radio);
    // TODO scan
    // TODO dfs
    // TODO traffic_separation
    blobmsg_close_table(&b, table);
}

static void fill_radio_currents(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_CURRENTS_NAME);

    // TODO primary_channel or second_channel?
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_CHANNEL_NAME, radio->chan);
    // txpower means current_eirp (Current Transmit Power EIRP)
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_TXPOWER_NAME, radio->txpower);
    // current opclass
    fill_radio_current_opclass(radio);
    // opclasses status
    fill_radio_opclasses_status(radio);

    blobmsg_close_table(&b, table);
}

static void fill_station_cabilities(struct staInfo *sta)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_CAPABILITIES_NAME);

    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_CAPA_REPORT_RESULT_NAME, sta->last_result_code);
    blobmsg_add_binary(&b, MAPAPI_STATION_ATTR_CAPA_REPORT_FRAME_NAME, sta->last_assoc, sta->last_assoc_len);

    // TODO MBOs
    if (sta->ies.rm_enabled)
        blobmsg_add_binary(&b, MAPAPI_STATION_ATTR_RM_IE_NAME, sta->ies.rm_enabled, sta->ies.rm_enabled[1]+2);

    blobmsg_close_table(&b, table);
}

static void fill_assoced_station_basic(struct staInfo *sta)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_STATION_ATTR_MAC_NAME, sta->mac);
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_BACKHAUL_NAME, sta->bSTA);
    // TODO if backhaul sta, record map_profile
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_LAST_ASSOC_TS_NAME, sta->last_assoc_ts);

    fill_station_cabilities(sta);

    blobmsg_close_table(&b, table);
}

static void fill_bss_assoced_stations(struct interfaceWifi *ifw)
{
    struct staInfo *sta;
    void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_ASSOC_STATIONS_NAME);
    dlist_for_each(sta, ifw->clients, l)
    {
        fill_assoced_station_basic(sta);
    }
    blobmsg_close_array(&b, list);
}

static void fill_radio_bss(struct interfaceWifi *ifw)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
    blobmsg_add_binary(&b, MAPAPI_BSS_ATTR_SSID_NAME, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_FRONTHAUL_NAME, ifw->bssInfo.fronthaul);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_BACKHAUL_NAME, ifw->bssInfo.backhaul);

    fill_bss_assoced_stations(ifw);
    blobmsg_close_table(&b, table);
}

static void fill_radio_bsses(struct radio *radio)
{
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_BSSES_NAME);
    uint32_t i;

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        if (ifw)
            fill_radio_bss(ifw);
    }
    blobmsg_close_array(&b, list);
}

static void fill_radio(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_RADIO_ATTR_ID_NAME, radio->uid);
    fill_radio_capabilities(radio);
    fill_radio_currents(radio);
    fill_radio_bsses(radio);
    blobmsg_close_table(&b, table);
}

static void fill_radios(struct alDevice *dev, dlist_head *radios)
{
    void *table = blobmsg_open_table(&b, NULL);

    blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr);
    blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_PROFILE_NAME, dev->profile);
    // TODO country_code
    fill_device_capabilities(dev);

    {
        void *list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_RADIOS_NAME);
        struct macAddressItem *rid;
        struct radio *radio;

        if (dlist_count(radios))
        {
            dlist_for_each(rid, *radios, l)
            {
                struct radio *radio = findDeviceRadio(dev, rid->mac);
                if (radio)
                    fill_radio(radio);
            }
        }
        else
        {
            dlist_for_each(radio, dev->radios, l)
            {
                fill_radio(radio);
            }
        }
        blobmsg_close_array(&b, list);
    }

    blobmsg_close_table(&b, table);
}

static void fill_wifi(dlist_head *devices, dlist_head *radios)
{
    void *list = blobmsg_open_array(&b, MAPAPI_NETWORK_ATTR_DEVICES_NAME);
    struct macAddressItem *alid;
    struct alDevice *dev;

    if (dlist_count(devices))
    {
        dlist_for_each(alid, *devices, l)
        {
            struct alDevice *dev = alDeviceFind(alid->mac);
            if (dev)
                fill_radios(dev, radios);
        }
    }
    else
    {
        dlist_for_each(dev, network, l)
        {
            fill_radios(dev, radios);
        }
    }

    blobmsg_close_array(&b, list);
}

static void fill_assoced_station_traffic_metrics(struct staInfo *sta)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_TRAFFIC_METRIC_NAME);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_TXBYTES_NAME, sta->traffic_metrics.tx_bytes);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_RXBYTES_NAME, sta->traffic_metrics.rx_bytes);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_TXPKTS_NAME, sta->traffic_metrics.tx_packets);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_RXPKTS_NAME, sta->traffic_metrics.rx_packets);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_TXERRS_NAME, sta->traffic_metrics.tx_errors);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_RXERRS_NAME, sta->traffic_metrics.rx_errors);
    blobmsg_add_u32(&b, MAPAPI_STATION_METRIC_ATTR_TXTRIES_NAME, sta->traffic_metrics.tx_tries);
    blobmsg_close_table(&b, table);
}

static void fill_station_stats(struct staInfo *sta)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_STATS_NAME);
    fill_assoced_station_link_metrics(sta);
    fill_assoced_station_traffic_metrics(sta);
    blobmsg_close_table(&b, table);
}

static void fill_stats_by_station(struct staInfo *sta)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_STATION_ATTR_MAC_NAME, sta->mac);
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_BACKHAUL_NAME, sta->bSTA);
    // TODO if backhaul sta, record map_profile
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_LAST_ASSOC_TS_NAME, sta->last_assoc_ts);
    fill_station_stats(sta);
    blobmsg_close_table(&b, table);
}

static void fill_stats_by_stations(struct interfaceWifi *ifw, dlist_head *stations)
{
    void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_STATIONS_NAME);
    struct macAddressItem *sta_mac;

    if (dlist_count(stations))
    {
        dlist_for_each(sta_mac, *stations, l)
        {
            struct staInfo *sta = interfaceFindStation(ifw, sta_mac->mac);
            if (sta)
                fill_stats_by_station(sta);
        }
    }
    else
    {
        struct staInfo *sta;
        dlist_for_each(sta, ifw->clients, l)
        {
            fill_stats_by_station(sta);
        }
    }

    blobmsg_close_array(&b, list);
}

static void fill_bss_espi(struct bssMetrics *metric)
{
    uint32_t i;

    for (i = 0; i < 4; i++)
    {
        if (metric->espis[i].valid)
        {
            void *table = blobmsg_open_table(&b, NULL);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_AC_NAME, i);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_FORMAT_NAME, metric->espis[i].format);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_WINDOW_NAME, metric->espis[i].window);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_EST_AIRTIME_NAME, metric->espis[i].est_airtime);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_DURATION_NAME, metric->espis[i].duration);
            blobmsg_close_table(&b, table);
        }
    }
}

static void fill_bss_stats(struct interfaceWifi *ifw)
{
    void *table = blobmsg_open_table(&b, MAPAPI_BSS_ATTR_STATS_NAME);
    blobmsg_add_u32(&b, MAPAPI_BSS_STAT_ATTR_CHUTIL_NAME, ifw->bssInfo.metrics.ch_util);
    blobmsg_add_u32(&b, MAPAPI_BSS_STAT_ATTR_CLIENT_NUM_NAME, dlist_count(&ifw->clients));
    {
        void *list = blobmsg_open_array(&b, MAPAPI_BSS_STAT_ATTR_ESPIS_NAME);
        fill_bss_espi(&ifw->bssInfo.metrics);
        blobmsg_close_array(&b, list);
    }
    // TODO traffic
    blobmsg_close_table(&b, table);
}

static void fill_stats_by_bss(struct interfaceWifi *ifw, dlist_head *stations)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
    blobmsg_add_binary(&b, MAPAPI_BSS_ATTR_SSID_NAME, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_FRONTHAUL_NAME, ifw->bssInfo.fronthaul);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_BACKHAUL_NAME, ifw->bssInfo.backhaul);
    fill_bss_stats(ifw);
    fill_stats_by_stations(ifw, stations);
    blobmsg_close_table(&b, table);
}

static void fill_stats_by_bsses(struct radio *radio, dlist_head *bsses, dlist_head *stations)
{
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_BSSES_NAME);
    struct macAddressItem *bssid;

    if (dlist_count(bsses))
    {
        dlist_for_each(bssid, *bsses, l)
        {
            struct interfaceWifi *ifw = radioFindInterfaceWifi(radio, bssid->mac);
            if (ifw)
                fill_stats_by_bss(ifw, stations);
        }
    }
    else
    {
        uint32_t i;
        for (i = 0; i < radio->configured_bsses.length; i++)
        {
            struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
            if (ifw)
                fill_stats_by_bss(ifw, stations);
        }
    }

    blobmsg_close_array(&b, list);
}

static void fill_radio_stats(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_STATS_NAME);
    blobmsg_add_u32(&b, MAPAPI_RADIO_STAT_ATTR_UTILIZATION_NAME, radio->ch_util);
    // TODO Noise
    // TODO Transmit
    // TODO ReceiveSelf
    // TODO ReceiveOther
    // TODO scan
    blobmsg_close_table(&b, table);
}

static void fill_stats_by_radio(struct radio *radio, dlist_head *bsses, dlist_head *stations)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_RADIO_ATTR_ID_NAME, radio->uid);
    fill_radio_currents(radio);
    fill_radio_stats(radio);
    fill_stats_by_bsses(radio, bsses, stations);
    blobmsg_close_table(&b, table);
}

static void fill_stats_by_radios(struct alDevice *dev, dlist_head *radios, dlist_head *bsses, dlist_head *stations)
{
    void *list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_RADIOS_NAME);
    struct macAddressItem *rid;

    if (dlist_count(radios))
    {
        dlist_for_each(rid, *radios, l)
        {
            struct radio *radio = findDeviceRadio(dev, rid->mac);
            if (radio)
                fill_stats_by_radio(radio, bsses, stations);
        }
    }
    else
    {
        struct radio *radio;
        dlist_for_each(radio, dev->radios, l)
        {
            fill_stats_by_radio(radio, bsses, stations);
        }
    }

    blobmsg_close_array(&b, list);
}

static void fill_stats_by_device(struct alDevice *dev, dlist_head *radios, dlist_head *bsses, dlist_head *stations)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr);
    blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_PROFILE_NAME, dev->profile);
    fill_stats_by_radios(dev, radios, bsses, stations);
    blobmsg_close_table(&b, table);
}

static void fill_stats(dlist_head *devices, dlist_head *radios, dlist_head *bsses, dlist_head *stations)
{
    void *list = blobmsg_open_array(&b, MAPAPI_NETWORK_ATTR_DEVICES_NAME);
    struct macAddressItem *alid;

    if (dlist_count(devices))
    {
        dlist_for_each(alid, *devices, l)
        {
            struct alDevice *dev = alDeviceFind(alid->mac);
            if (dev)
                fill_stats_by_device(dev, radios, bsses, stations);
        }
    }
    else
    {
        struct alDevice *dev;
        dlist_for_each(dev, network, l)
        {
            fill_stats_by_device(dev, radios, bsses, stations);
        }
    }

    blobmsg_close_array(&b, list);
}

static int mapapi_get_network_devices(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    dlist_head devices;
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    const char *output_fmt;
    int mac_fmt=0;
    blob_buf_init(&b, 0);
    dlist_head_init(&devices);

    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));
    if (tb[MAPAPI_GET_MAP_ATTR_DEVICES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_DEVICES], array_mac_to_dlist, &devices, MAPAPI_DEVICE_ATTR_ALID_NAME);

    if (tb[MAPAPI_GET_MAP_ATTR_FMT_CTL]){
        output_fmt = blobmsg_get_string(tb[MAPAPI_GET_MAP_ATTR_FMT_CTL]);
        if(strcmp(output_fmt, "strings") == 0){
            mac_fmt = 1;
        }
    }

    fill_devices(&devices, fill_device, mac_fmt);
    dlist_free_items(&devices, struct macAddressItem, l);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_network_topology(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    const char *output_fmt;
    int mac_fmt = 0;
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (tb[MAPAPI_GET_MAP_ATTR_FMT_CTL]){
		output_fmt = blobmsg_get_string(tb[MAPAPI_GET_MAP_ATTR_FMT_CTL]);
		if(strcmp(output_fmt, "strings") == 0){
			mac_fmt = 1;
		}
	}

    fill_topology(mac_fmt);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_network_map_topology(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{

    blob_buf_init(&b, 0);
    link_aldev_list();
    fill_topology_map(list_head);
    list_free(&list_head);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_current_map_role(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    char map_role[16] = {"unconfigured"};
    blob_buf_init(&b, 0);

    if (local_device && local_device->is_map_controller)
        strcpy(map_role,"controller");
    else if (local_device && local_device->is_map_agent)
        strcpy(map_role,"agent");

    blobmsg_add_string(&b, "map_role", map_role);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_controller_mac(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    fill_controller_mac();
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_network_wifi(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    DEFINE_DLIST_HEAD(devices);
    DEFINE_DLIST_HEAD(radios);

    blob_buf_init(&b, 0);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (tb[MAPAPI_GET_MAP_ATTR_DEVICES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_DEVICES], array_mac_to_dlist, &devices, MAPAPI_DEVICE_ATTR_ALID_NAME);

    if (tb[MAPAPI_GET_MAP_ATTR_RADIOS])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_RADIOS], array_mac_to_dlist, &radios, MAPAPI_RADIO_ATTR_ID_NAME);

    fill_wifi(&devices, &radios);

    dlist_free_items(&devices, struct macAddressItem, l);
    dlist_free_items(&radios, struct macAddressItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_network_unassoc(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    DEFINE_DLIST_HEAD(devices);

    blob_buf_init(&b, 0);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));
    if (tb[MAPAPI_GET_MAP_ATTR_DEVICES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_DEVICES], array_mac_to_dlist, &devices, MAPAPI_DEVICE_ATTR_ALID_NAME);

    fill_devices(&devices, fill_device_unassoc, 0);
    dlist_free_items(&devices, struct macAddressItem, l);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_network_nearby(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    const char *output_fmt;
    int mac_fmt = 0;
    DEFINE_DLIST_HEAD(devices);

    blob_buf_init(&b, 0);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));
    if (tb[MAPAPI_GET_MAP_ATTR_DEVICES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_DEVICES], array_mac_to_dlist, &devices, MAPAPI_DEVICE_ATTR_ALID_NAME);

    if (tb[MAPAPI_GET_MAP_ATTR_FMT_CTL]){
        output_fmt = blobmsg_get_string(tb[MAPAPI_GET_MAP_ATTR_FMT_CTL]);
        if(strcmp(output_fmt, "strings") == 0){
            mac_fmt = 1;
        }
    }

    fill_devices(&devices, fill_device_nearby, mac_fmt);
    dlist_free_items(&devices, struct macAddressItem, l);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_network_stats(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    DEFINE_DLIST_HEAD(devices);
    DEFINE_DLIST_HEAD(radios);
    DEFINE_DLIST_HEAD(bsses);
    DEFINE_DLIST_HEAD(stations);

    blob_buf_init(&b, 0);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (tb[MAPAPI_GET_MAP_ATTR_DEVICES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_DEVICES], array_mac_to_dlist, &devices, MAPAPI_DEVICE_ATTR_ALID_NAME);
    if (tb[MAPAPI_GET_MAP_ATTR_RADIOS])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_RADIOS], array_mac_to_dlist, &radios, MAPAPI_RADIO_ATTR_ID_NAME);
    if (tb[MAPAPI_GET_MAP_ATTR_BSSES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_BSSES], array_mac_to_dlist, &bsses, MAPAPI_BSS_ATTR_BSSID_NAME);
    if (tb[MAPAPI_GET_MAP_ATTR_STATIONS])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_STATIONS], array_mac_to_dlist, &stations, MAPAPI_STATION_ATTR_MAC_NAME);

    fill_stats(&devices, &radios, &bsses, &stations);

    dlist_free_items(&devices, struct macAddressItem, l);
    dlist_free_items(&radios, struct macAddressItem, l);
    dlist_free_items(&bsses, struct macAddressItem, l);
    dlist_free_items(&stations, struct macAddressItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

static const struct ubus_method mapapi_network_methods[] = {
    UBUS_METHOD(MAPAPI_METHOD_GET_NETWORK_DEVICES_NAME, mapapi_get_network_devices, mapapi_get_map_policy),
    UBUS_METHOD_NOARG(MAPAPI_METHOD_GET_NETWORK_TOPOLOGY_NAME, mapapi_get_network_topology),
    UBUS_METHOD(MAPAPI_METHOD_GET_NETWORK_WIFI_NAME, mapapi_get_network_wifi, mapapi_get_map_policy),
    UBUS_METHOD(MAPAPI_METHOD_GET_NETWORK_UNASSOC_STATIONS_NAME, mapapi_get_network_unassoc, mapapi_get_map_policy),
    UBUS_METHOD(MAPAPI_METHOD_GET_NETWORK_NEARBY_STATIONS_NAME, mapapi_get_network_nearby, mapapi_get_map_policy),
    UBUS_METHOD(MAPAPI_METHOD_GET_NETWORK_STATS_NAME, mapapi_get_network_stats, mapapi_get_map_policy),
    UBUS_METHOD_NOARG(MAPAPI_METHOD_GET_NETWORK_TOPOLOGY_MAP_NAME, mapapi_get_network_map_topology),
    UBUS_METHOD_NOARG(MAPAPI_METHOD_GET_CURRENT_MAP_ROLE, mapapi_get_current_map_role),
    UBUS_METHOD_NOARG(MAPAPI_METHOD_GET_CONTROLLER_MAC, mapapi_get_controller_mac),
};

static struct ubus_object_type mapapi_network_obj_type =
UBUS_OBJECT_TYPE(MAPAPI_NETWORK_OBJ_NAME, mapapi_network_methods);

static struct ubus_object mapapi_network_obj = {
    .name = MAPAPI_NETWORK_OBJ_NAME,
    .type = &mapapi_network_obj_type,
    .methods = mapapi_network_methods,
    .n_methods = ARRAY_SIZE(mapapi_network_methods),
};

struct ubus_object *get_mapapi_network_obj(void)
{
    return &mapapi_network_obj;
}
