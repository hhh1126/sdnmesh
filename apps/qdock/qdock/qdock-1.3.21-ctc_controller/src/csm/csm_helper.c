/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/
#include <pthread.h>
#ifdef Q_OPENWRT
#include "json-c/json.h"
#else
#include "json/json.h"
#endif
#include "csm.h"

#define PPREFIX "csmcore: "

radio_table_t *csm_radio_find(struct sta_sdb *db, uint8_t *mac)
{
	return (radio_table_t *) stadb_sta_find(db, mac);
}

radio_table_t *csm_radio_find_or_add(struct sta_sdb *db, uint8_t *mac)
{
	CSM_DEBUG(PPREFIX "find or add radio %" MACFMT, MACARG(mac));
	return (radio_table_t *) stadb_sta_find_or_add(db, mac);
}

void csm_radio_put(radio_table_t *radio)
{
	csm_put(radio);
}

void *csm_bss_add(struct sta_sdb *db, uint8_t * mac)
{
	return (bss_table_t *) stadb_sta_add(db, mac);
}

void *csm_bss_find(struct sta_sdb *db, uint8_t * mac)
{
	return (bss_table_t *) stadb_sta_find(db, mac);
}

static void csm_devid_early_init(stah_t * stah, void *data1, void *data2)
{
	devid_table_t *devid = (devid_table_t *)stah;
	devid->bss_lh = (struct list_head)LIST_HEAD_INIT(devid->bss_lh);
}

devid_table_t *csm_devid_find(struct sta_sdb *db, uint8_t * mac)
{
	return (devid_table_t *) stadb_sta_find(db, mac);
}

devid_table_t *csm_devid_find_or_add(struct sta_sdb * db,
					    uint8_t * mac)
{
	return (devid_table_t *) stadb_sta_find_or_add_ext1(db, mac,
							  csm_devid_early_init,
							  NULL, NULL);
}

static void csm_bss_link_to_devid(struct sta_sdb *db, uint8_t *dev_id, bss_table_t *bss)
{
	devid_table_t *devid = NULL;
	COPYMAC(bss->dev_id, dev_id);
	devid = csm_devid_find_or_add(db, dev_id);
	if(!devid)
		return;

	CSM_LOCK(devid);
	list_add_tail(&bss->lh, &devid->bss_lh);
	CSM_UNLOCK(devid);

	csm_put(devid);
}

static void csm_bss_early_init(stah_t * stah, void *data1, void *data2)
{
	csmpluginctx_t *pluginctx = (csmpluginctx_t *) data1;
	uint8_t *dev_id = (uint8_t *)data2;
	uint8_t default_devid[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
	csmctx_t *csm;

	bss_table_t *bss = (bss_table_t *) stah;
	bss->flag |=
	    (pluginctx->type ==
	     CSM_PLUGIN_TYPE_COMM ? BSS_FLAG_REMOTE : 0);
	bss->drv = pluginctx;
	bss->flag &= (~BSS_FLAG_MBO);
	bss->flag &= (~BSS_FLAG_ACR);
	/* fall back to vap type for old RPE */
	bss->iftype = NODE_TYPE_VAP;

	if(!dev_id)
		dev_id = default_devid;
	csm = GET_CSMCTX(data1);
	csm_bss_link_to_devid(csm->devid_db, dev_id, bss);
}

bss_table_t *csm_bss_find_or_add(struct sta_sdb *db, uint8_t *device_id,
					uint8_t * mac, void *drv)
{
	return (bss_table_t *) stadb_sta_find_or_add_ext1(db, mac,
							  csm_bss_early_init,
							  drv, device_id);
}

void csm_bss_put(bss_table_t * bss)
{
	csm_put(bss);
}

sta_table_t *csm_station_add(struct sta_sdb * db, uint8_t * mac)
{
	return (sta_table_t *) stadb_sta_add(db, mac);
}

sta_table_t *csm_station_find(struct sta_sdb * db, uint8_t * mac)
{
	return (sta_table_t *) stadb_sta_find(db, mac);
}

sta_table_t *csm_station_find_or_add(struct sta_sdb * db,
					    uint8_t * mac)
{
	return (sta_table_t *) stadb_sta_find_or_add(db, mac);
}

void csm_station_put(sta_table_t * sta)
{
	csm_put(sta);
}

void csm_seen_bssid_del(sta_table_t *sta, uint8_t *bssid)
{
	sta_seen_bssid_t *stasbssid, *stabssid_tmp;
	sta_seen_mdid_t *stasmdid;
	list_for_each_entry(stasmdid, &sta->seen_mdid_lh, lh) {
		list_for_each_entry_safe(stasbssid, stabssid_tmp, &stasmdid->seen_bssid_lh, lh) {
			if (!bssid || MACEQUAL(stasbssid->bssid, bssid)) {
				list_del(&stasbssid->lh);
				CSM_FREE(stasbssid);
			}
		}
	}
}

sta_seen_bssid_t *csm_seen_bssid_find_or_add(sta_table_t * sta,
					     uint8_t * mdid,
					     uint8_t * bssid)
{
	sta_seen_bssid_t *staseenbssid = NULL, *stasbssid, *stabssid_tmp;
	sta_seen_mdid_t *staseenmdid = NULL, *stasmdid;

	if (IS_ZERO_MAC(bssid))
		return NULL;

	list_for_each_entry(stasmdid, &sta->seen_mdid_lh, lh) {
		if (MDIDEQUAL(stasmdid->mdid, mdid))
			staseenmdid = stasmdid;
		list_for_each_entry_safe(stasbssid, stabssid_tmp, &stasmdid->seen_bssid_lh, lh) {
			if (MACEQUAL(stasbssid->bssid, bssid)) {
				if (staseenmdid == stasmdid) {
					return stasbssid;
				} else {
					/* find in other mdid list, remove it */
					staseenbssid = stasbssid;
					list_del(&stasbssid->lh);
				}
			}
		}
	}

	if (staseenmdid == NULL) {
		staseenmdid = CSM_CALLOC(1, sizeof(sta_seen_mdid_t));
		if (staseenmdid) {
			memcpy(staseenmdid->mdid, mdid, MDID_LEN);
			staseenmdid->seen_bssid_lh = (struct list_head)
			    LIST_HEAD_INIT(staseenmdid->seen_bssid_lh);
			list_add_tail(&staseenmdid->lh,
				      &sta->seen_mdid_lh);
		}
	}

	if (staseenmdid) {
		/* find in other mdid list, link it into current mdid list */
		if (staseenbssid) {
			list_add_tail(&staseenbssid->lh, &staseenmdid->seen_bssid_lh);
			stasbssid = staseenbssid;
		} else {
			stasbssid = CSM_CALLOC(1, sizeof(sta_seen_bssid_t));
			if (stasbssid) {
				COPYMAC(stasbssid->bssid, bssid);
				list_add_tail(&stasbssid->lh,
					      &staseenmdid->seen_bssid_lh);
			}
		}
	} else {
		stasbssid = NULL;
	}
	return stasbssid;
}

uint32_t csm_get_seen_bssid_age(sta_seen_bssid_t *seen_bssid)
{
	timestamp_t now;

	now = csm_get_timestamp();
	return (uint32_t)((int32_t)now - (int32_t)seen_bssid->last_ts);
}

csmmsgh_t *csm_get_msg_body(csmmsg_t * csmmsg)
{
	return (csmmsgh_t *) csmmsg->msgbody;
}

csmmsg_t *csm_new_msg(uint16_t id, uint8_t version, uint8_t coding,
		      uint8_t * bssid, size_t len)
{
	csmmsg_t *msg = CSM_NEW(sizeof(csmmsg_t) + len);
	csmmsgh_t *h;
	if (msg) {
		msg->msgbody = (char *)(msg + 1);
		h = (csmmsgh_t *) msg->msgbody;
		h->id = host_to_le16(id);
		h->api_ver = version;
		h->coding = coding;
		COPYMAC(h->bssid, bssid);
		h->payload_len = host_to_le16(len - sizeof(csmmsgh_t));
	}
	return msg;
}

csmmsg_t *csm_new_empty_msg(size_t len)
{
	csmmsg_t *msg = (csmmsg_t *) CSM_NEW(sizeof(csmmsg_t) + len);
	if (msg) {
		msg->msgbody = (char *) (msg + 1);
	}
	return msg;
}

void csm_unref_msg(csmmsg_t * msg)
{
	csm_put((csmobj_t *) msg);
}

void
csm_set_free_data(csmobj_t * obj, free_data_func free_data, void *data)
{
	obj->free_data = free_data;
	obj->data = data;
}

void csm_msg_set_body(csmmsg_t * msg, char *body, int len)
{
	msg->msgbody = body;
}

csmmsg_t *csm_ref_msg(csmmsg_t * msg)
{
	return csm_get((csmobj_t *) msg);
}

int csm_push_cmd_bss(void *ctx, bss_table_t * bss, csmmsg_t * action)
{
	int ret = -1, locked = 0;

	csmctx_t *csm;
	drvctx_t *drv;
	csm_cmd_handler *handler;
	csmmsgh_t *h = csm_get_msg_body(action);
	uint16_t id = le_to_host16(h->id);

	handler = csm_get_cmd_handler(id);
	if (unlikely(handler == NULL)) {
		CSM_DEBUG(PPREFIX "unknown command id = %d", id);
		goto bail;
	}

	csm = GET_CSMCTX(ctx);
	CSM_DEBUG(PPREFIX "command=%d[%s] to bss %" MACFMT "=%p", id,
		  handler->name, MACARG(h->bssid), bss);

	drv = (drvctx_t *) bss->drv;
	if (drv->pluginctx.type != CSM_PLUGIN_TYPE_DRIVER)
		goto bail;

	csm_get(bss);

	if (drv->pluginctx.ready == 0) {
		locked = 1;
		CSM_LOCK(drv);
	}

	if ((((csmpluginctx_t *) (bss->drv))->type ==
	     CSM_PLUGIN_TYPE_DRIVER) && ((drv = (drvctx_t *) bss->drv)))
		ret =
		    drv->drv.plugin.dplugin->ops.action(drv->drv.instance,
							action);

	if (locked)
		CSM_UNLOCK(drv);

	if (handler->efunc)
		ret = handler->efunc(csm, h, bss, drv);

      bail:
	csm_unref_msg(action);
	return ret;
}


int csm_push_cmd_ext(csmctx_t *csm, void *ctx, csmmsg_t * action)
{
	int ret = -1;

	bss_table_t *bss;
	drvctx_t *drv = NULL;
	csm_cmd_handler *handler;
	csmmsgh_t *h = csm_get_msg_body(action);
	uint16_t id = le_to_host16(h->id);

	handler = csm_get_cmd_handler(id);
	if (unlikely(handler == NULL)) {
		CSM_DEBUG(PPREFIX "unknown command id = %04x", id);
		goto bail;
	}

	if (!csm && ctx)
		csm = GET_CSMCTX(ctx);
	if (!csm)
		goto bail;

	bss = csm_bss_find(csm->bss_db, h->bssid);
	if (unlikely(bss == NULL)) {
		CSM_DEBUG(PPREFIX "unknown bss %" MACFMT "",
			  MACARG(h->bssid));
		goto bail;
	}
	CSM_DEBUG(PPREFIX "command=%d[%s] to bss %" MACFMT "=%p", id,
		  handler->name, MACARG(h->bssid), bss);

	if ((((csmpluginctx_t *) (bss->drv))->type ==
	     CSM_PLUGIN_TYPE_DRIVER) && ((drv = (drvctx_t *) bss->drv)))
		ret =
		    drv->drv.plugin.dplugin->ops.action(drv->drv.instance,
							action);
	if (handler->efunc)
		ret = handler->efunc(csm, h, bss, drv);

      bail:
	csm_unref_msg(action);
	return ret;
}

int csm_push_cmd(void *ctx, csmmsg_t * action)
{
	return csm_push_cmd_ext(NULL, ctx, action);
}

int csm_tx_rpe_msg(void *ctx, uint8_t *bssid, uint8_t *msg, uint32_t len)
{
	csmmsg_t *action = NULL;
	csmmsgh_t *rpe_msg = (csmmsgh_t *)msg;
	uint16_t payload_len;

	if (!ctx || !msg || len < sizeof(csmmsgh_t))
		return -1;

	payload_len = le_to_host16(rpe_msg->payload_len);
	if (len < payload_len + sizeof(csmmsgh_t)) {
		CSM_WARNING(PPREFIX "Discard the RPE command(0x%x): len(%u < %u",
			le_to_host16(rpe_msg->id), len,
			payload_len + sizeof(csmmsgh_t));
		return -1;
	}

	if (bssid && !MACADDR_EQ(bssid, rpe_msg->bssid)) {
		CSM_WARNING(PPREFIX "Discard the RPE command(0x%x): bssid is different",
			le_to_host16(rpe_msg->id));
		return -1;
	}

	action = csm_new_empty_msg(0);
	if (!action)
		return -1;
	csm_msg_set_body(action, (char *)msg,
		payload_len + sizeof(csmmsgh_t));

	return csm_push_cmd(ctx, action);
}

static int csm_send_event_to_logic(mobility_domain_t * md, csmmsg_t * msg)
{
	int i;
	for (i = 0; i < LOGIC_ROLE_MAX; i++) {
		if (md->instance_mask & (1 << i)) {
			md->logic[i].plugin.splugin->ops.recv_event(md->
								    logic
								    [i].
								    instance,
								    msg);
		}
	}
	return 0;
}

static void csm_process_intf_status_deleted_bss(csmctx_t *csm, csmmsgh_t *h, bss_table_t *bss)
{
	uint32_t status = le_to_host32(((evt_intf_status_t *)h)->status);

	if (status == RPE_INTF_STATE_DELETED)
		csm_bss_delete(csm, bss);
}

int csm_push_event(void *ctx, csmmsg_t * event)
{
	int ret = -1;
	csmmsgh_t *h = csm_get_msg_body(event);
	drvctx_t *drv;
	csmctx_t *csm;
	bss_table_t *bss;
	uint16_t id = le_to_host16(h->id);

	csm_event_handler *handler;
	handler = csm_get_event_handler(id);

	if (unlikely(handler == NULL)) {
		CSM_DEBUG(PPREFIX "unknown  event id = %d", id);
		goto bail;
	}

	drv = (drvctx_t *) ctx;
	csm = (csmctx_t *) (drv->pluginctx.csm);
	bss = csm_bss_find(csm->bss_db, h->bssid);

	CSM_DEBUG(PPREFIX "event=%d[%s] to bss %" MACFMT "=%p", id,
		  handler->name, MACARG(h->bssid), bss);

	pthread_mutex_lock(&csm->lock);
	if (handler->efunc) {
		/* efunc will put the bss, so get bss for it */
		if (bss)
			csm_get(bss);
		ret = handler->efunc(csm, h, bss, drv);
	}

	if (bss) {
		if (NULL == bss->md)
			bss->md = csm_find_mobility_domain(csm, bss->mdid);
		if (bss->md)
			ret = csm_send_event_to_logic(bss->md, event);
		/* if evt is intf_status_deleted, it can only be deleted this bss
		 * after sync "S2M_BSS_Update" to master */
		if (handler->id == EVENT_INTF_STATUS)
			csm_process_intf_status_deleted_bss(csm, h, bss);
		csm_put(bss);
	}
	pthread_mutex_unlock(&csm->lock);

bail:
	csm_unref_msg(event);
	return ret;
}

struct sta_sdb *csm_get_station_table(void *ctx)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;

	return csm->station_db;
}

struct sta_sdb *csm_get_bss_table(void *ctx)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;

	return csm->bss_db;
}

#define MAX_TABLE_SIZE 256
static stah_t **csm_table_list_safe_get_by_filter(struct sta_sdb *db,
						  table_filter_func_t
						  filter, void *data1,
						  void *data2)
{
	stah_t **stalist, **tmplist;
	int i, max_size;

	max_size = db->max_size ? db->max_size : MAX_TABLE_SIZE;
	stalist = CSM_CALLOC(1, (max_size + 1) * sizeof(stah_t *));

	CSM_LOCK(db);

	if (stalist == NULL)
		goto bail;
	tmplist = stalist;
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah;
		struct list_head *l = &db->stalh[i];
		list_for_each_entry(stah, l, lh) {
			CSM_LOCK(stah);
			if (filter(stah, data1, data2)) {
				CSM_UNLOCK(stah);
				*(tmplist++) = csm_get(stah);
				if ((--max_size) <= 1)
					break;
			} else
				CSM_UNLOCK(stah);
		}
	}

      bail:
	CSM_UNLOCK(db);
	return stalist;
}

static void csm_table_list_release(stah_t ** stalist)
{
	if (stalist) {
		stah_t **tmplist = stalist;
		while (*tmplist) {
			csm_put(*tmplist);
			tmplist++;
		}
		CSM_FREE(stalist);
	}
}

sta_table_t **csm_station_list_get_by_filter(void *ctx,
					     table_filter_func_t filter,
					     void *data1, void *data2)
{
	struct sta_sdb *db = csm_get_station_table(ctx);
	return (sta_table_t **) csm_table_list_safe_get_by_filter(db,
								  filter,
								  data1,
								  data2);
}

void csm_station_list_put(sta_table_t ** stalist)
{
	csm_table_list_release((stah_t **) stalist);
}

bss_table_t **csm_bss_list_get_by_filter(void *ctx,
					 table_filter_func_t filter,
					 void *data1, void *data2)
{
	struct sta_sdb *db = csm_get_bss_table(ctx);
	return (bss_table_t **) csm_table_list_safe_get_by_filter(db,
								  filter,
								  data1,
								  data2);
}

void csm_bss_list_put(bss_table_t ** bsslist)
{
	csm_table_list_release((stah_t **) bsslist);
}


#define CSM_DB_SNAPSHOT 0

struct sta_sdb *csm_get_radio_table(void *ctx)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
	struct sta_sdb *db = csm->radio_db;
	CSM_LOCK(db);
	return db;
}

void csm_put_radio_table(struct sta_sdb *db)
{
	CSM_UNLOCK(db);
}

struct sta_sdb *csm_get_devid_table(void *ctx)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
	struct sta_sdb *db = csm->devid_db;
	CSM_LOCK(db);
	return db;
}

void csm_put_devid_table(struct sta_sdb *db)
{
	CSM_UNLOCK(db);
}

struct sta_sdb *csm_get_station_table_snapshot(void *ctx)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
#if CSM_DB_SNAPSHOT
	struct sta_sdb *db = csm->station_db_snapshot;
#else
	struct sta_sdb *db = csm->station_db;
#endif

	CSM_LOCK(db);
#if CSM_DB_SNAPSHOT
	stadb_fast_sync(db, csm->station_db);
#endif
	return db;

}

void csm_put_station_table_snapshot(struct sta_sdb *db)
{
	CSM_UNLOCK(db);
}

struct sta_sdb *csm_get_bss_table_snapshot(void *ctx)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
#if CSM_DB_SNAPSHOT
	struct sta_sdb *db = csm->bss_db_snapshot;
#else
	struct sta_sdb *db = csm->bss_db;
#endif

	CSM_LOCK(db);
#if CSM_DB_SNAPSHOT
	stadb_fast_sync(db, csm->bss_db);
#endif
	return db;

}

void csm_put_bss_table_snapshot(struct sta_sdb *db)
{
	CSM_UNLOCK(db);
}

stah_t *csm_find_station_snapshot(void *ctx, uint8_t * mac)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
#if CSM_DB_SNAPSHOT
	struct sta_sdb *db = csm->station_db_snapshot;
#else
	struct sta_sdb *db = csm->station_db;
#endif
	stah_t *sta = stadb_sta_find(db, mac);

	if (!sta)
		return NULL;

	CSM_LOCK(sta);

	return sta;
}

void csm_put_station_snapshot(stah_t * sta)
{
	CSM_UNLOCK(sta);
	csm_put(sta);
}

stah_t *csm_find_bss_snapshot(void *ctx, uint8_t * mac)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
#if CSM_DB_SNAPSHOT
	struct sta_sdb *db = csm->bss_db_snapshot;
#else
	struct sta_sdb *db = csm->bss_db;
#endif
	stah_t *bss = stadb_sta_find(db, mac);

	if (!bss)
		return NULL;

	CSM_LOCK(bss);

	return bss;
}

void csm_put_bss_snapshot(stah_t * bss)
{
	CSM_UNLOCK(bss);
	csm_put(bss);
}

int csm_deauth_sta(csmctx_t * csm, uint8_t * bss_mac, uint8_t * mac,
		uint16_t code)
{
	csmmsg_t *msg;
	uint8_t bssid[ETH_ALEN] = { 0 };

	if (bss_mac)
		COPYMAC(bssid, bss_mac);
	if (code) {
		msg =
		    csm_new_msg(CMD_DEAUTH, CSM_VER_1, CSM_CODING_FIXED,
				bssid, sizeof(cmd_deauth_t));
		if (msg) {
			cmd_deauth_t *cmd_d =
			    (cmd_deauth_t *) csm_get_msg_body(msg);
			COPYMAC(cmd_d->sta_mac, mac);
			cmd_d->reasoncode = host_to_le16(code);
			csm_push_cmd_ext(csm, NULL, msg);
		}
	}
	return 0;
}

static void csm_blacklist_sta(void *ctx, uint8_t * bssid, uint8_t * mac,
			      int blacklist)
{
	uint16_t alloc_mac;
	csmmsg_t *msg;

	if (blacklist)
		alloc_mac = MAC_FILTER_DENY_MAC;
	else
		alloc_mac = MAC_FILTER_ALLOW_MAC;

	msg = csm_new_msg(CMD_STA_MAC_FILTER,
			  CSM_VER_1, CSM_CODING_FIXED, bssid,
			  sizeof(cmd_mac_filter_t));
	if (msg) {
		cmd_mac_filter_t *cmd_mf =
		    (cmd_mac_filter_t *) csm_get_msg_body(msg);
		COPYMAC(cmd_mf->sta_mac, mac);
		cmd_mf->allow_mac = host_to_le16(alloc_mac);
		csm_push_cmd(ctx, msg);
	}
}

int
csm_deauth_and_blacklist_sta(void *ctx, uint8_t * bss_mac, uint8_t * mac,
			     uint16_t code, int flag)
{
	csmmsg_t *msg;
	uint8_t bssid[ETH_ALEN] = { 0 };
	int blacklist = (flag & CSM_DEAUTH_FLAG_BLACKLIST);
	uint16_t cmd = (flag & CSM_DEAUTH_FLAG_DISASSOC) ?
		CMD_DISASSOC : CMD_DEAUTH;

	if (bss_mac)
		COPYMAC(bssid, bss_mac);

	if (code) {
		msg =
		    csm_new_msg(cmd, CSM_VER_1, CSM_CODING_FIXED,
				bssid, sizeof(cmd_deauth_t));

		if (msg) {
			cmd_deauth_t *cmd_d =
			    (cmd_deauth_t *) csm_get_msg_body(msg);
			COPYMAC(cmd_d->sta_mac, mac);
			cmd_d->reasoncode = host_to_le16(code);
			csm_push_cmd(ctx, msg);
		}

		if (blacklist) {
			csm_blacklist_sta(ctx, bssid, mac, blacklist);
		}
	} else {
		csm_blacklist_sta(ctx, bssid, mac, blacklist);
	}
	return 0;
}

int csm_process_bss_table_tlv(void *ctx, uint8_t *device_id, uint8_t * msg_payload)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
	return csm_decode_bss_tlv(csm, NULL, device_id, (csmmsgh_t *) msg_payload,
				  ctx);
}

int csm_process_sta_table_tlv(void *ctx, uint8_t * msg_payload)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
	return csm_decode_station_tlv(csm, NULL,
				      (csmmsgh_t *) msg_payload);
}

static void csm_bss_get_sta_stats(void *data1, void *data2)
{
	csmmsg_t *msg;
	bss_table_t *bss = (bss_table_t *) data1;
	msg =
	    csm_new_msg(CMD_GET_STA_STATS, CSM_VER_2, CSM_CODING_FIXED,
			bss->h.mac, sizeof(cmd_get_sta_stats_t));
	if (msg) {
		cmd_get_sta_stats_t *cmd_g = (cmd_get_sta_stats_t *)
		    csm_get_msg_body(msg);
		if (data2) {
			memcpy(cmd_g->sta_mac, data2, ETH_ALEN);
		} else
			memset(cmd_g->sta_mac, 0xff, ETH_ALEN);
		csm_push_cmd(bss->drv, msg);
	}
}

static void csm_bss_get_neighbour_stats(void *data1, void *data2)
{
	csmmsg_t *msg;
	bss_table_t *bss = (bss_table_t *) data1;
	msg =
	    csm_new_msg(CMD_GET_NONASSOC_STATS, CSM_VER_2,
			CSM_CODING_FIXED, bss->h.mac,
			sizeof(cmd_get_nonassoc_stats_t));
	if (msg) {
		cmd_get_nonassoc_stats_t *cmd_g =
		    (cmd_get_nonassoc_stats_t *) csm_get_msg_body(msg);
		if (data2) {
			memcpy(cmd_g->sta_mac, data2, ETH_ALEN);
		} else
			memset(cmd_g->sta_mac, 0xff, ETH_ALEN);
		csm_push_cmd(bss->drv, msg);
	}
}

static void
csm_bss_send_start_fat_monitor(bss_table_t * bss, uint32_t period)
{
	csmmsg_t *msg;
	msg =
	    csm_new_msg(CMD_START_FAT_MONITORING, CSM_VER_2, CSM_CODING_FIXED,
			bss->h.mac, sizeof(cmd_start_fat_monitoring_t));
	if (msg) {
		cmd_start_fat_monitoring_t *cmd_m = (cmd_start_fat_monitoring_t *)
		    csm_get_msg_body(msg);
		cmd_m->ifname_size = strlen(bss->ifname);
		strcpy(cmd_m->ifname, bss->ifname);
		cmd_m->fat_period = host_to_le32(period);
		csm_push_cmd_bss(bss->drv, bss, msg);
	}
}

static void
csm_bss_send_stop_fat_monitor(bss_table_t * bss)
{
}

static void
csm_bss_send_start_monitor(bss_table_t * bss, int period, int duty_cycle)
{
	csmmsg_t *msg;
	msg =
	    csm_new_msg(CMD_MONITOR_START, CSM_VER_2, CSM_CODING_FIXED,
			bss->h.mac, sizeof(cmd_monitor_start_t));
	if (msg) {
		cmd_monitor_start_t *cmd_m = (cmd_monitor_start_t *)
		    csm_get_msg_body(msg);
		cmd_m->ifname_size = strlen(bss->ifname);
		strcpy(cmd_m->ifname, bss->ifname);
		cmd_m->peroid = host_to_le16(period);
		cmd_m->duty_cycle = host_to_le16(duty_cycle);
		csm_push_cmd_bss(bss->drv, bss, msg);
	}
}

static void
csm_bss_send_stop_monitor(bss_table_t * bss, int period, int duty_cycle)
{
	csmmsg_t *msg;
	msg =
	    csm_new_msg(CMD_MONITOR_STOP, CSM_VER_2, CSM_CODING_FIXED,
			bss->h.mac, sizeof(cmd_monitor_stop_t));
	if (msg) {
		cmd_monitor_stop_t *cmd_m = (cmd_monitor_stop_t *)
		    csm_get_msg_body(msg);
		cmd_m->ifname_size = strlen(bss->ifname);
		strcpy(cmd_m->ifname, bss->ifname);
		csm_push_cmd_bss(bss->drv, bss, msg);
	}
}

static void
csm_bss_send_spdia_ctrl(uint8_t *sta_mac, bss_table_t *bss, int period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth)
{
	csmmsg_t *msg = csm_new_msg(CMD_SPDIA_CTRL, CSM_RPE_VER(7), CSM_CODING_FIXED,
		bss->h.mac, sizeof(cmd_spdia_config_ctrl_t));
	if (msg) {
		cmd_spdia_config_ctrl_t *cmd = (cmd_spdia_config_ctrl_t *)
			csm_get_msg_body(msg);
		COPYMAC(cmd->sta, sta_mac);
		cmd->period = host_to_le16(period);
		cmd->spdia_feature = (reorder & CSM_REORDER_MASK) |
			((mode & CSM_OPERATION_MODE_MASK) << CSM_SPDIA_MODE_SHIFT);
		cmd->spdia_ng = ng;
		cmd->spdia_smooth = smooth;
		csm_push_cmd(bss->drv, msg);
	}
}

static void csm_bss_get_fat_info(void *data1, void *data2)
{
	csmmsg_t *msg;
	bss_table_t *bss = (bss_table_t *) data1;
	msg =
	    csm_new_msg(CMD_GET_INTF_INFO, CSM_VER_2, CSM_CODING_FIXED,
			bss->h.mac, sizeof(cmd_get_intf_info_t));
	if (msg) {
		cmd_get_intf_info_t *cmd_g = (cmd_get_intf_info_t *)
		    csm_get_msg_body(msg);
		cmd_g->ifname_size = strlen(bss->ifname);
		cmd_g->specifier = host_to_le32(CMD_GET_INTF_INFO_SPEC_FAT);
		strcpy(cmd_g->ifname, bss->ifname);
		csm_push_cmd(bss->drv, msg);
	}
}

static int
csm_bss_add_sta_stats_monitor(stah_t * stah, void *ctx, void *param)
{
	bss_table_t *bss = (bss_table_t *) stah;
	uint32_t secs = *((uint32_t *)param);
	uint32_t msecs = secs * 1000;
	csm_get(bss);
	CSM_LOCK(bss);
	bss->stats_event_period = secs;
	csm_timer_register(ctx, msecs, csm_bss_get_sta_stats, bss, NULL,
			   1);
	csm_timer_register(ctx, msecs, csm_bss_get_neighbour_stats, bss,
			   NULL, 1);
	CSM_UNLOCK(bss);
	return 0;
}

static int
csm_bss_remove_sta_stats_monitor(stah_t * stah, void *ctx, void *param)
{
	bss_table_t *bss = (bss_table_t *) stah;

	CSM_LOCK(bss);
	csm_timer_cancel(ctx, csm_bss_get_sta_stats, bss, NULL);
	csm_timer_cancel(ctx, csm_bss_get_neighbour_stats, bss, NULL);
	CSM_UNLOCK(bss);
	csm_put(bss);
	return 0;
}

static int csm_bss_add_fat_monitor(stah_t * stah, void *ctx, void *param)
{
	bss_table_t *bss = (bss_table_t *) stah;
	uint32_t secs = *((uint32_t *)param);
	uint32_t msecs = secs * 1000;
	csm_get(bss);
	csm_bss_send_start_fat_monitor(bss, secs);
	CSM_LOCK(bss);
	csm_timer_register(ctx, msecs, csm_bss_get_fat_info, bss, NULL,
			   1);
	CSM_UNLOCK(bss);
	return 0;
}

static int
csm_bss_remove_fat_monitor(stah_t * stah, void *ctx, void *param)
{
	bss_table_t *bss = (bss_table_t *) stah;

	csm_bss_send_stop_fat_monitor(bss);
	CSM_LOCK(bss);
	csm_timer_cancel(ctx, csm_bss_get_fat_info, bss, NULL);
	CSM_UNLOCK(bss);
	csm_put(bss);
	return 0;
}

static void start_monitor_free_param_cb(void *ctx, void *param)
{
	if (param) {
		CSM_FREE(param);
		param = NULL;
	}
}

void csm_start_fat_monitor(void *handle, uint32_t secs)
{
	csmctx_t *csm = GET_CSMCTX(handle);
	struct sta_sdb *db = csm->bss_db;
	uint32_t *p_secs = CSM_MALLOC(sizeof(uint32_t));
	*p_secs = secs;
	CSM_LOCK(db);
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_CREATE, 1,
				    csm_bss_add_fat_monitor,
				    csm, (void *) p_secs, start_monitor_free_param_cb);

	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_DESTROY, 0,
				    csm_bss_remove_fat_monitor,
				    csm, NULL, NULL);

	CSM_UNLOCK(db);
}

void csm_start_sta_stats_monitor(void *handle, uint32_t secs)
{
	csmctx_t *csm = GET_CSMCTX(handle);
	struct sta_sdb *db = csm->bss_db;
	uint32_t *p_secs = CSM_MALLOC(sizeof(uint32_t));
	*p_secs = secs;
	CSM_LOCK(db);
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_CREATE, 1,
				    csm_bss_add_sta_stats_monitor,
				    csm, (void *) p_secs, start_monitor_free_param_cb);

	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_DESTROY, 0,
				    csm_bss_remove_sta_stats_monitor,
				    csm, NULL, NULL);

	CSM_UNLOCK(db);
}

int
csm_start_monitor(void *handle, uint8_t *bssid,
				  uint32_t period, uint32_t duty_cycle)
{
	csmctx_t *csm = GET_CSMCTX(handle);
	bss_table_t *bss = csm_bss_find(csm->bss_db, bssid);
	if (NULL == bss)
		return -1;
	if (duty_cycle)
		csm_bss_send_start_monitor(bss, period, duty_cycle);
	else
		csm_bss_send_stop_monitor(bss, period, duty_cycle);

	csm_bss_put(bss);

	return 0;
}

int csm_check_spdia_sta_monitoring_num_and_add(bss_table_t *bss,
	uint8_t *mac)
{
	struct list_head *spdia_sta_head = &bss->spdia_sta_head;
	spdia_sta_t *spdia_sta;
	int count = 0;

	CSM_LOCK(bss);
	list_for_each_entry(spdia_sta, spdia_sta_head, lh) {
		count++;
		if (MACADDR_EQ(mac, spdia_sta->mac)) {
			CSM_UNLOCK(bss);
			return 0;
		}
	}
	CSM_UNLOCK(bss);

	if (count >= bss->spdia_sta_support_count) {
		CSM_WARNING(PPREFIX "current spdia monitoring sta count %d is exceeding the "
			"max allowable count %d\n",
			count, bss->spdia_sta_support_count);
		return -1;
	}

	spdia_sta = CSM_CALLOC(1, sizeof(spdia_sta_t));
	if (!spdia_sta)
		return -1;

	memcpy(spdia_sta->mac, mac, ETH_ALEN);
	CSM_LOCK(bss);
	list_add_tail(&spdia_sta->lh, spdia_sta_head);
	CSM_UNLOCK(bss);

	return count;
}

int csm_remove_spdia_monitoring_sta(bss_table_t *bss,
	uint8_t *mac)
{
	struct list_head *spdia_sta_head = &bss->spdia_sta_head;
	spdia_sta_t *spdia_sta, *tmp;

	CSM_LOCK(bss);
	list_for_each_entry_safe(spdia_sta, tmp, spdia_sta_head, lh) {
		if (MACADDR_EQ(mac, spdia_sta->mac)) {
			list_del(&spdia_sta->lh);
			CSM_FREE(spdia_sta);
			break;
		}
	}
	CSM_UNLOCK(bss);
	return 0;
}

static void
csm_delete_spdia_sta_by_bss(bss_table_t *bss)
{
	struct list_head *spdia_sta_head = &bss->spdia_sta_head;
	spdia_sta_t *spdia_sta;

	CSM_LOCK(bss);
	while (!list_empty(spdia_sta_head)) {
		spdia_sta = list_first_entry(spdia_sta_head, spdia_sta_t, lh);
		list_del(&spdia_sta->lh);
		CSM_UNLOCK(bss);

		csm_bss_send_spdia_ctrl(spdia_sta->mac, bss, 0, 0, 0, 0, 0);
		CSM_FREE(spdia_sta);
		CSM_LOCK(bss);
        }
        CSM_UNLOCK(bss);
}

#define CSM_SPDIA_MODE_DATA_SHIFT	0
#define CSM_SPDIA_MODE_NDP_SHIFT	1

int csm_spdia_sta_ctrl(void *handle, uint8_t *mac, uint32_t period,
	uint8_t reorder, uint8_t mode, uint8_t ng, uint8_t smooth)
{
	csmctx_t *csm;
	sta_table_t *sta = NULL;
	bss_table_t *bss = NULL;
	int ret = -1;

	if (!handle || !mac)
		return -1;

	csm = GET_CSMCTX(handle);
	sta = csm_station_find(csm->station_db, mac);
	if (!sta) {
		CSM_INFO(PPREFIX "spdia ctrl %" MACFMT
			" failed: sta not found", MACARG(mac));
		goto __out;
	}

	if (!STA_IS_ASSOCIATED(sta)) {
		CSM_INFO(PPREFIX "spdia ctrl %" MACFMT
			" failed: sta is not associated", MACARG(mac));
		goto __out;
	}

	bss = csm_bss_find(csm->bss_db, sta->assoc_info.assoc_bssid);
	if (!bss) {
		CSM_WARNING(PPREFIX "spdia ctrl %" MACFMT
			" failed: associated bss %" MACFMT " is not found",
			MACARG(mac), MACARG(sta->assoc_info.assoc_bssid));
		goto __out;
	}

	if (!(bss->driver_cap & CSM_DRV_CAPAB_SUPPORT_SPDIA)) {
		CSM_WARNING(PPREFIX "spdia ctrl %" MACFMT
			" failed: associated bss %" MACFMT " not support SPDIA feature",
			MACARG(mac), MACARG(bss->h.mac));
		goto __out;
	}

	if (bss->iftype == NODE_TYPE_STA)
                csm_delete_spdia_sta_by_bss(bss);

	if (!(bss->spdia_supported_feature & CSM_DRV_SPDIA_REORDER)) {
		CSM_WARNING(PPREFIX "spdia configure bss %" MACFMT
			" failed: not support SPDIA reorder feature",
			MACARG(bss->h.mac));
		goto __out;
	}

	if (!(bss->spdia_supported_feature & CSM_DRV_SPDIA_MODE_DATA) &&
			(mode & (1 << CSM_SPDIA_MODE_DATA_SHIFT))) {
		CSM_WARNING(PPREFIX "spdia configure sta %" MACFMT
			" to data mode failed: not support in SPDIA mode feature",
			MACARG(mac));
		goto __out;
	}

	if (!(bss->spdia_supported_feature & CSM_DRV_SPDIA_MODE_NDP) &&
			(mode & (1 << CSM_SPDIA_MODE_NDP_SHIFT))) {
		CSM_WARNING(PPREFIX "spdia configure sta %" MACFMT
			" to ndp mode failed: not support in SPDIA mode feature",
			MACARG(mac));
		goto __out;
	}

	if (period > 0 && (csm_check_spdia_sta_monitoring_num_and_add(bss, mac)
		< 0))
		goto __out;

	csm_bss_send_spdia_ctrl(sta->h.mac, bss, period, reorder, mode, ng, smooth);

	if (period == 0)
		csm_remove_spdia_monitoring_sta(bss, mac);

	ret = 0;

__out:
	if (bss)
		csm_bss_put(bss);
	if (sta)
		csm_station_put(sta);

	return ret;
}

static int
csm_set_param_value(csm_param_value * value, int type,
		    struct json_object *jvalue)
{
	switch (type) {
	case CSM_PARAM_OBJECT:
		value->object = jvalue;
		break;
	case CSM_PARAM_INT:
		if (json_object_is_type(jvalue, json_type_int)) {
			value->int_value = json_object_get_int(jvalue);
			break;
		}
	case CSM_PARAM_DOUBLE:
		if (json_object_is_type(jvalue, json_type_double)) {
			value->double_value =
			    json_object_get_double(jvalue);
			break;
		}
	case CSM_PARAM_STRING:
		if (json_object_is_type(jvalue, json_type_string)) {
			value->str_value = json_object_get_string(jvalue);
			break;
		}
	default:
		return -3;
		break;
	}
	return 0;
}

static int
__csm_param_get_value(struct json_object *parent, csm_param_value *value,
	const char *key, int type, int index)
{
	struct json_object *param;

	if (json_object_object_get_ex(parent, key, &param)) {
		if (index < 0) {
			return csm_set_param_value(value, type, param);
		} else {
			if (json_object_is_type(param, json_type_array)) {
				struct json_object *jvalue;
				if ((jvalue =
				     (json_object_array_get_idx
				      (param, index)))) {
					return csm_set_param_value(value,
								   type,
								   jvalue);
				} else
					return -3;

			} else
				return -3;
		}
	} else
		return -2;
}

int csm_object_param_get_value(void *handle, const void *object,
	csm_param_value *value, const char *key, int type, int index)
{
	if (!handle|| !object || !value || !key)
		return -1;

	return __csm_param_get_value((struct json_object *)object,
		value, key, type, index);
}

int
csm_param_get_value(void *handle, csm_param_value * value, const char *key,
		    int type, int index)
{
	struct json_object *params;
	if ((handle == NULL) || (value == NULL) || (key == NULL))
		return -1;
	params = GET_CSMINITPARAM(handle);

	return __csm_param_get_value(params, value, key, type, index);
}

void *csm_averager_create(uint16_t shift)
{
	uint32_t size = (1 << shift);
	csm_averager *avg = CSM_CALLOC(1,
				       (sizeof(csm_averager) +
					(sizeof(csm_history_t) << shift)));
	if (avg) {
		avg->shift = shift;
		avg->size = size;
	}
	return avg;
}

void csm_averager_destroy(void *p)
{
	if (p)
		CSM_FREE(p);
}

int32_t csm_averager_get_value(void *p, uint16_t age)
{
	csm_averager *avg = (csm_averager *) p;
	timestamp_t now = csm_get_timestamp();
	uint32_t ind;
	uint32_t latest, nums = 0;
	int32_t span, total = 0;

	if (!avg)
		return 0;

	latest = ind = CSM_AVERAGER_GET_PREV_IND(avg, avg->index);

	do {
		span = csm_get_timespan(now, avg->history[ind].ts);
		if (span > age)
			break;

		total += avg->history[ind].value;
		nums++;
		ind = CSM_AVERAGER_GET_PREV_IND(avg, ind);
	} while (ind != latest);

	if (!nums)
		return avg->history[latest].value;

	if (total < 0)
		return -((-total) / nums);
	else
		return (total / nums);
}

int csm_averager_add_value(void *p, int32_t value, timestamp_t ts)
{
	csm_averager *avg = (csm_averager *) p;
	uint32_t ind;
	if (!avg)
		return 0;

	ind = CSM_AVERAGER_GET_PREV_IND(avg, avg->index);
	if (ts && avg->history[ind].ts == ts
		&& avg->history[ind].value == value)
		return 0;
	avg->history[avg->index].value = value;
	avg->history[avg->index].ts = ts;
	avg->index++;
	if (avg->index >= avg->size)
		avg->index = 0;
	if (avg->nums < avg->size)
		avg->nums++;
	return 1;
}

void csm_averager_set_value(void *p, int32_t value)
{
	int i;
	csm_averager *avg = (csm_averager *) p;

	if (avg) {
		avg->index = 0;
		avg->nums = 0;
		for (i = 0; i < avg->size; i++) {
			avg->history[i].value = value;
			avg->history[i].ts = 0;
		}
	}
}

static inline void csm_remove_bss_from_radio(radio_table_t *radio, bss_table_t *bss)
{
	CSM_LOCK(radio);
	list_del(&bss->radio_lh);
	CSM_UNLOCK(radio);

	bss->radio = NULL;
}

static inline void csm_add_bss_into_radio(radio_table_t *radio, bss_table_t *bss)
{
	CSM_LOCK(radio);
	list_add_tail(&bss->radio_lh, &radio->bss_head);
	CSM_UNLOCK(radio);

	bss->radio = radio;
}

static void csm_radio_delete_related(csmctx_t *csm, bss_table_t *bss)
{
	if (!bss || !bss->radio)
		return;

	csm_remove_bss_from_radio(bss->radio, bss);
}

int csm_devid_delete_related(csmctx_t *csm, bss_table_t *bss)
{
	struct sta_sdb *db = csm->devid_db;
	devid_table_t *devid = NULL;

	devid = csm_devid_find(db, bss->dev_id);
	if(devid) {
		CSM_LOCK(devid);
		list_del(&bss->lh);
		CSM_UNLOCK(devid);

		CSM_LOCK(db);
		if(list_empty(&devid->bss_lh))
			stadb_sta_delete_unlock(db, (stah_t *)devid);
		csm_put(devid);
		CSM_UNLOCK(db);
	}
	return 0;
}

int csm_station_delete_related(csmctx_t * csm, uint8_t * mac)
{
	struct sta_sdb *db = csm->station_db;
	int i;
	struct list_head *l;
	sta_seen_bssid_t *stasbssid, *tmpb;
	sta_seen_mdid_t *stasmdid, *tmpm;

	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah, *stasafeh;
		l = &db->stalh[i];
		list_for_each_entry_safe(stah, stasafeh, l, lh) {
			sta_table_t *sta = (sta_table_t *) stah;
			CSM_LOCK(sta);
			if (FLAG_IS_SET
			    (sta->flag, STATION_FLAG_ASSOCIATED)) {
				if (MACEQUAL
				    (sta->assoc_info.assoc_bssid, mac))
					CLEAR_FLAG(sta->flag,
						   STATION_FLAG_ASSOCIATED);
			}
			list_for_each_entry_safe(stasmdid, tmpm,
						 &sta->seen_mdid_lh, lh) {
				list_for_each_entry_safe(stasbssid, tmpb,
							 &stasmdid->seen_bssid_lh,
							 lh) {

					if (MACEQUAL
					    (mac, stasbssid->bssid)) {
						list_del(&stasbssid->lh);
						CSM_FREE(stasbssid);
					}
				}
				if (list_empty(&stasmdid->seen_bssid_lh)) {
					list_del(&stasmdid->lh);
					CSM_FREE(stasmdid);
				}
			}
			if (list_empty(&sta->seen_mdid_lh)) {
				CSM_UNLOCK(sta);
				stadb_sta_delete_unlock(db, stah);
			} else
				CSM_UNLOCK(sta);

		}
	}

	CSM_UNLOCK(db);
	return 0;
}

void csm_bss_delete(csmctx_t *csm, bss_table_t *bss)
{
	struct sta_sdb *db = csm->bss_db;

	csm_station_delete_related(csm, bss->h.mac);
	csm_devid_delete_related(csm, bss);
	csm_radio_delete_related(csm, bss);

	stadb_sta_delete_unlock(db, (stah_t *)bss);
}

int csm_bss_delete_remote(void *ctx)
{
	csmctx_t *csm = GET_CSMCTX(ctx);
	struct sta_sdb *db = csm->bss_db;
	int i;
	struct list_head *l;

	CSM_LOCK(db);

	for (i = 0; i < db->hash_size; i++) {
		stah_t *bssh, *bsssafeh;
		l = &db->stalh[i];
		list_for_each_entry_safe(bssh, bsssafeh, l, lh) {
			bss_table_t *bss = (bss_table_t *) bssh;
			if (bss->flag & BSS_FLAG_REMOTE)
				csm_bss_delete(csm, bss);
		}
	}

	CSM_UNLOCK(db);
	return 0;
}

uint32_t csm_station_age_out(stah_t * stah, stah_t ** pcandidateh,
			     void *data)
{
	uint32_t result = 0;
	sta_table_t *sta = (sta_table_t *) stah;
	sta_table_t *candidate = (sta_table_t *) (*pcandidateh);
	timestamp_t now;
	sta_table_ageout_config_t *config =
	    (sta_table_ageout_config_t *) data;

	if (STA_IS_ASSOCIATED(sta))
		goto bail;

	now = csm_get_timestamp();
	if (now - sta->last_rssi_ts > config->age_timeout) {
		result = 1;
		goto bail;
	}

	if (candidate == NULL) {
		*pcandidateh = stah;
	} else if (candidate->last_rssi_ts > sta->last_rssi_ts) {
		*pcandidateh = stah;
	}

      bail:
	return result;
}

int csm_sta_update_assoc_bss(csmctx_t * csm, uint8_t * bssid,
			     uint8_t * sta_addr)
{
	sta_table_t *sta =
	    csm_station_find_or_add(csm->station_db, sta_addr);

	if (sta) {
		bss_table_t *bss = csm_bss_find(csm->bss_db, bssid);
		if (bss) {
			CSM_LOCK(sta);
			CSM_TOUCH(&sta->h);
			STA_UPDATE_ASSOC_BSS(sta, bssid, bss->mdid);
			CSM_UNLOCK(sta);
			csm_bss_put(bss);
		}

		csm_station_put(sta);
	}

	return 0;
}

int csm_bss_trans_req(void *ctx, uint8_t * bss, uint8_t * payload,
		      uint32_t payload_len)
{
	csmmsg_t *msg =
	    csm_new_msg(CMD_BSS_TRANS_REQ, CSM_VER_2, CSM_CODING_FIXED,
			bss, sizeof(csmmsgh_t) + payload_len);
	if (msg) {
		csmmsgh_t *h = (csmmsgh_t *) msg->msgbody;
		memcpy(h->payload, payload, payload_len);
		csm_push_cmd(ctx, msg);
		return 0;
	}
	return -1;
}

int csm_station_delete_association(void *ctx, uint8_t * bssid,
				   uint8_t * sta_mac)
{
	csmctx_t *csm = GET_CSMCTX(ctx);
	sta_table_t *sta = csm_station_find(csm->station_db, sta_mac);

	if (sta) {
		CSM_LOCK(sta);
		STA_UPDATE_DISASSOCIATATION_BSSID(sta, bssid);
		CSM_UNLOCK(sta);
		csm_station_put(sta);
	}
	return 0;
}

int csm_bss_update(void *ctx, uint8_t * bssid, uint16_t status)
{
	csmctx_t *csm;
	bss_table_t *bss;

	if (!ctx || !bssid)
		return -1;
	csm = GET_CSMCTX(ctx);
	bss = csm_bss_find(csm->bss_db, bssid);
	csm_process_intf_status(csm, bss, status);
	if (bss)
		csm_bss_put(bss);
	return 0;
}

static uint32_t csmd_add_one_erw_entry(uint8_t *frm, csm_erw_entry_t *entry)
{
	uint8_t *pos = frm;
	uint8_t tmp[4];

	pos += csm_encap_tlv(pos, TLVTYPE_STA_MAC, entry->sta, ETH_ALEN);
	memset(tmp, 0, 4);
	tmp[0] = entry->action;

	if (entry->action == CSM_ERW_ACTION_ADD) {
		tmp[0] |= entry->rssi_mode;
		tmp[1] = entry->mask;
	}
	pos += csm_encap_tlv(pos, TLVTYPE_BL_MASK, tmp, 4);
	if (entry->action == CSM_ERW_ACTION_ADD) {
		if (entry->rssi_mode != CSM_ERW_RSSI_MODE_NONE)
			pos += csm_encap_tlv_uint32(pos, TLVTYPE_RSSI, entry->rssi);
		*(uint16_t *)tmp = host_to_le16(entry->reject_mode);
		pos += csm_encap_tlv(pos, TLVTYPE_STATUS_CODE, tmp, 4);
	}

	if (entry->reject_payload_len
		&& entry->reject_payload) {
		memcpy(pos, entry->reject_payload, entry->reject_payload_len);
		pos += CSM_IE_LEN(entry->reject_payload_len);
	}

	return (pos - frm);
}

/* see how to encode the erw entry */
static inline uint16_t csmd_one_erw_entry_len(csm_erw_entry_t *entry)
{
	uint16_t tlv_len, payload_len = 0;
	if (entry->reject_payload_len
		&& entry->reject_payload)
		payload_len = entry->reject_payload_len;
	tlv_len = sizeof(tlv_t) + csm_tlv_vlen(TLVTYPE_STA_MAC)
			+ sizeof(tlv_t) + csm_tlv_vlen(TLVTYPE_BL_MASK);
	if (entry->action == CSM_ERW_ACTION_ADD) {
		if (entry->rssi_mode != CSM_ERW_RSSI_MODE_NONE)
			tlv_len += sizeof(tlv_t) + csm_tlv_vlen(TLVTYPE_RSSI);
		tlv_len += sizeof(tlv_t) + csm_tlv_vlen(TLVTYPE_STATUS_CODE);
	}
	return tlv_len + CSM_IE_LEN(payload_len);
}

static inline csmmsg_t *csmd_alloc_erw_req(uint8_t *bssid, uint32_t len)
{
	return csm_new_msg(CMD_STA_MAC_FILTER, CSM_RPE_VER(5), CSM_CODING_TLV,
			bssid, sizeof(csmmsgh_t) + len);
}

static void csm_build_and_push_erw_cmd(void *ctx, uint8_t *bss_mac, uint32_t len,
	csm_erw_list_t *list, uint32_t start, uint32_t end)
{
	csmmsg_t *msg;
	csmmsgh_t *h;
	uint8_t *pos;
	uint32_t i = start;

	msg = csmd_alloc_erw_req(bss_mac, len);
	if (!msg)
		return;
	h = (csmmsgh_t *)csm_get_msg_body(msg);
	pos = h->payload;
	for (; i < end; i++)
		pos += csmd_add_one_erw_entry(pos, list->entries + i);
	csm_push_cmd(ctx, msg);
}

int csm_set_erw(void *ctx, uint8_t *bss_mac, csm_erw_list_t *list)
{
	uint32_t nums, i, start = 0, len = 0, entry_len;

	if (!ctx || !bss_mac || !list)
		return -1;
	nums = list->nums;
	if (nums > CSM_MAX_ERW_ENTRIES)
		nums = CSM_MAX_ERW_ENTRIES;

	for (i = 0; i < nums; i++) {
		entry_len = csmd_one_erw_entry_len(list->entries + i);
		if (len + entry_len + sizeof(csmmsgh_t) > CSM_RPE_MAX_LEN) {
			if (start < i) {
				csm_build_and_push_erw_cmd(ctx, bss_mac, len, list, start, i);
				/* recheck current index */
				i--;
			} else {
				CSM_WARNING(PPREFIX "erw entry %u payload len %u for %" MACFMT " is too large",
					i, list->entries[i].reject_payload_len, MACARG(list->entries[i].sta));
			}
			/* for next erw RPE command */
			len = 0;
			start = i + 1;
		} else
			len += entry_len;
	}

	csm_build_and_push_erw_cmd(ctx, bss_mac, len, list, start, i);
	return 0;
}

#define HT_BWNUMS	(BW_40M + 1)
#define VHT_BWNUMS	(BW_160M + 1)
#define HT_MAXSS	4
#define VHT_MAXSS	8
static const uint32_t g_ht_max_phyrates[HT_BWNUMS][HT_MAXSS] = {
	{72, 144, 217, 289},
	{150, 300, 450, 600}
};

static const uint32_t g_vht_max_phyrates[VHT_BWNUMS][VHT_MAXSS] = {
	{87, 173, 289, 347, 433, 578, 607, 693},
	{200, 400, 600, 800, 1000, 1200, 1400, 1600},
	{433, 867, 1300, 1733, 2167, 2340, 3033, 3467},
	{867, 1733, 2340, 3467, 4333, 5200, 6067, 6933}
};

static uint32_t csm_get_maxphyrate_by_phytype(int vht_supported, bw_e maxbw, uint8_t rxss)
{
	uint32_t maxphyrate = 54;
	if (0 == rxss)
		return maxphyrate;

	rxss--;
	if (1 == vht_supported
		&& maxbw < VHT_BWNUMS
		&& rxss < VHT_MAXSS)
		maxphyrate = g_vht_max_phyrates[maxbw][rxss];
	else if (maxbw < HT_BWNUMS
		&& rxss < HT_MAXSS)
		maxphyrate = g_ht_max_phyrates[maxbw][rxss];

	return maxphyrate;
}

uint32_t csm_get_sta_supported_maxphyrate(sta_table_t *sta)
{
	bw_e sta_bw;
	sta_cap_t *cap = &sta->sta_info.supported_capability;
	uint8_t sta_rxss = sta->sta_info.supported_rxss;
	int vht_supported = 0;
	if (cap->vht_supported) {
		sta_bw = cap->vht_bw ? BW_160M : BW_80M;
		vht_supported = 1;
	} else {
		sta_bw = cap->ht_bw ? BW_40M : BW_20M;
	}

	return csm_get_maxphyrate_by_phytype(vht_supported, sta_bw, sta_rxss);
}

bw_e csm_get_bss_bandwidth(bss_table_t *bss)
{
	bw_e bw = bss->bss_capability.ht_bw;
	if (bss->bss_capability.vht_supported
		&& check_vht_operation_ie(bss->vht_operation)) {
		switch (bss->bss_capability.vht_bw) {
		case 1:
			if (IEEE80211_VHTOP_GET_CENTERFREQ1(
				(struct ieee80211_ie_vhtop *)(bss->vht_operation)))
				bw = BW_160M;
			else
				bw = BW_80M;
			break;

		case 2:
		case 3:
			bw = BW_160M;

		default:
			break;

		}
	}
	return bw;
}

uint32_t csm_get_bss_supported_maxphyrate(bss_table_t *bss)
{
	bw_e bss_bw = csm_get_bss_bandwidth(bss);
	sta_cap_t *cap = &bss->bss_capability;

	return csm_get_maxphyrate_by_phytype(cap->vht_supported, bss_bw, bss->txss);
}

int csm_process_frame(uint8_t wh_included, uint8_t *frame, uint32_t len,
	void *process_ctx, process_ieee80211_fixed_t process_fixed_cb,
	process_ieee80211_ie_t process_ie_cb)
{
	struct ieee80211_frame *wh = NULL;
	uint8_t *frm = frame, *efrm = frame + len;
	int fix_len = 0;
	if (!frame)
		return -1;
	if (wh_included) {
		if (len < sizeof(*wh))
			return -1;
		wh = (struct ieee80211_frame *)frame;
		frm = (uint8_t *)(wh + 1);
	}
	if (process_fixed_cb)
		fix_len = process_fixed_cb(process_ctx, frm, efrm);
	if (fix_len < 0)
		return fix_len;
	frm += fix_len;

	while (frm + 2 <= efrm) {
		if (frm + 2 + frm[1] > efrm)
			return -1;
		if (process_ie_cb)
			process_ie_cb(process_ctx, frm);
		frm += frm[1] + 2;
	}
	if (frm != efrm) {
		CSM_WARNING(PPREFIX "Drop the frame: frame length is parsed failed");
		return -1;
	}
	return 0;
}

int csm_check_frame_ie_len(uint32_t ie_offset, uint8_t *frame, uint32_t len)
{
	if (len < ie_offset)
		return -1;

	return csm_process_frame(0, frame + ie_offset, len - ie_offset,
		NULL, NULL, NULL);
}

void csm_parse_rpe_tlv(void *ctx, uint8_t *frm, uint16_t frm_len,
	init_block_t init_cb, check_block_t check_cb,
	parse_ie_t parse_cb, process_block_t process_cb)
{
	tlv_t *t;
	uint16_t type, len;
	int16_t min_len = 0;
	void *ies = NULL;

	if (init_cb)
		init_cb();

	while (frm_len > sizeof(*t)) {
		t = (tlv_t *)frm;
		type = le_to_host16(t->type);
		len = le_to_host16(t->len);
		min_len = csm_tlv_vlen(type);

		if (frm_len < len + sizeof(*t))  {
			CSM_WARNING("Drop Tag(%u): len(%u) is over left frame len(%u)",
				type, len, frm_len);
			return;
		}

		if (min_len >= 0 && min_len > len) {
			CSM_WARNING("Drop Tag(%u): len(%u) is not over min len(%u)",
				type, len, min_len);
			goto _next;
		}

		if (ies && check_cb && check_cb(type))
			process_cb(ctx, ies, frm, 1);

		parse_cb(&ies, frm, type, len);

_next:
		frm += (sizeof(*t) + CSM_IE_LEN(len));
		frm_len -= (sizeof(*t) + CSM_IE_LEN(len));
	}

	if (ies)
		process_cb(ctx, ies, frm, 0);
}

static const char *us_op_class_cc[] = {
	"US", "CA", NULL
};

static const char *eu_op_class_cc[] = {
	"AL", "AM", "AT", "AZ", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE",
	"DK", "EE", "EL", "ES", "FI", "FR", "GE", "HR", "HU", "IE", "IS", "IT",
	"LI", "LT", "LU", "LV", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT",
	"RO", "RS", "RU", "SE", "SI", "SK", "TR", "UA", "UK", "EU", NULL
};

static const char *jp_op_class_cc[] = {
	"JP", NULL
};

static const char *cn_op_class_cc[] = {
	"CN", NULL
};

static const char **g_cc_regs[] = {
	us_op_class_cc,
	eu_op_class_cc,
	jp_op_class_cc,
	cn_op_class_cc
};

struct operating_class_map {
	uint8_t op_class;
	uint8_t regs[4];	/* us/eu/jp/cn */
};

static const struct operating_class_map g_cc_opclass[] = {
	{ 81,	{ 12, 4, 30, 7 } },
	{ 82,	{ 0, 0, 31, 0 } },
	{ 83,	{ 32, 11, 56, 8 } },
	{ 84,	{ 33, 12, 57, 9 } },
	{ 115,	{ 1, 1, 1, 1 } },
	{ 116,	{ 22, 5, 36, 4 } },
	{ 117,	{ 27, 8, 41, 0 } },
	{ 118,	{ 2, 2, 32, 2 } },
	{ 119,	{ 23, 6, 37, 5 } },
	{ 120,	{ 28, 9, 42, 0 } },
	{ 121,	{ 4, 3, 34, 0 } },
	{ 122,	{ 24, 7, 39, 0 } },
	{ 123,	{ 29, 10, 44, 0 } },
	{ 124,	{ 3, 0, 0, 0 } },
	{ 125,	{ 5, 17, 0, 3 } },
	{ 126,	{ 25, 0, 0, 6 } },
	{ 127,	{ 30, 0, 0, 0 } },
	{ 128,	{ 128, 128, 128, 128 } },
	{ 129,	{ 129, 129, 129, 129 } },
	{ 130,	{ 130, 130, 130, 130 } },
};

uint8_t csm_get_global_opclass(uint8_t *cc, uint8_t opclass)
{
	int i = 0, j, k;

	if (opclass >= 81)
		return opclass;

	for (i = 0; i < 4; i++) {
		j = 0;
		while (g_cc_regs[i][j]) {
			if (strncasecmp((const char *)cc, g_cc_regs[i][j], 2) == 0)
				break;
			j++;
		}
		if (g_cc_regs[i][j])
			break;
	}
	if (i >= 4)
		return opclass;

	for (k = 0; k < ARRAY_SIZE(g_cc_opclass); k++) {
		if (g_cc_opclass[k].regs[i] == opclass)
			break;
	}
	if (k >= ARRAY_SIZE(g_cc_opclass))
		return opclass;

	return (g_cc_opclass[k].op_class);
}

struct operating_class_table {
	uint8_t op_class;
	uint8_t bw;
	uint8_t chans[32];
};

static const struct operating_class_table gb_oper_class_table[] = {
	{81, BW_20M, {1,2,3,4,5,6,7,8,9,10,11,12,13,0}},
	{82, BW_20M, {14,0}},
	{83, BW_40M, {1,2,3,4,5,6,7,8,9,0}},
	{84, BW_40M, {5,6,7,8,9,10,11,12,13,0}},
	{115, BW_20M, {36,40,44,48,0}},
	{116, BW_40M, {36,44,0}},
	{117, BW_40M, {40,48,0}},
	{118, BW_20M, {52,56,60,64,0}},
	{119, BW_40M, {52,60,0}},
	{120, BW_40M, {56,64,0}},
	{121, BW_20M, {100,104,108,112,116,120,124,128,132,136,140,144,0}},
	{122, BW_40M, {100,108,116,124,132,140,0}},
	{123, BW_40M, {104,112,120,128,136,144,0}},
	{124, BW_20M, {149,153,157,161,0}},
	{126, BW_40M, {149,157,0}},
	{127, BW_40M, {153,161,0}},
	{128, BW_80M, {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,0}},
	{130, BW_80M, {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,0}},
};

static struct band_info g_bands[BAND_IDX_MAX] = {
	/* {band_chan_step, band_first_chan, band_chan_cnt} */
	{1, 1, 13},
	{1, 14, 1},
	{4, 36, 4},
	{4, 52, 4},
	{4, 100, 12},
	{4, 149, 4},
	/* isolate chan 165 for IOT as per sniffer capture */
	{4, 165, 1},
};

uint8_t csm_get_bw20_opclass(uint8_t ch)
{
	int i, j;
	for (i = 0; i < ARRAY_SIZE(gb_oper_class_table); i++) {
		const struct operating_class_table *opclass = gb_oper_class_table + i;
		if (BW_20M != opclass->bw)
			continue;
		for (j = 0; j < 32; j++) {
			if (!opclass->chans[j])
				break;
			if (ch == opclass->chans[j])
				return opclass->op_class;
		}
	}
	return 0;
}

struct band_info *csm_get_band_info(int band_idx)
{
	if (band_idx >= BAND_IDX_MAX)
		return NULL;

	return &g_bands[band_idx];
}

static int csm_get_band_chan_step(int chan)
{
	struct band_info *band;
	int band_idx;
	int temp_chan;
	int chan_cnt;
	int chan_step;

	for (band_idx = 0; band_idx < BAND_IDX_MAX; band_idx++) {
		band = csm_get_band_info(band_idx);
		if (!band)
			continue;

		temp_chan = band->band_first_chan;
		chan_cnt = band->band_chan_cnt;
		chan_step = band->band_chan_step;

		while (chan_cnt--) {
			if (temp_chan == chan)
				return chan_step;
			temp_chan += chan_step;
		}
	}

	return -1;
}

void csm_parse_supp_chan(sta_table_t *sta,
	uint8_t *frm, uint8_t len)
{
	int chan_tuples;
	uint8_t band;
	uint8_t chan;
	uint8_t chan_len;
	int8_t chan_step;
	uint16_t reset_2g, reset_5g;
	int i;

	if (!sta || !frm || !len)
		return;

	reset_2g = reset_5g = 1;
	chan_tuples = len / 2;
	for (i = 0; i < chan_tuples; i++) {
		chan = *(frm + i * 2);
		band = csm_channel_to_band(chan);
		chan_len = *(frm + 1 + i * 2);
		chan_step = csm_get_band_chan_step(chan);
		if (chan_step < 0)
			continue;

		/* Support Channel IE included, reset and parse */
		if (reset_2g && band == BAND_2G) {
			reset_2g = 0;
			sta->assoc_info.suppchan_2g_existed = 1;
			memset(sta->assoc_info.suppchan_2g_masks, 0, CHAN_MASK_BYTES);
		}
		if (reset_5g && band == BAND_5G) {
			reset_5g = 0;
			sta->assoc_info.suppchan_5g_existed = 1;
			memset(sta->assoc_info.suppchan_5g_masks, 0, CHAN_MASK_BYTES);
		}

		while (chan_len--) {
			if (band == BAND_2G)
				setbit(sta->assoc_info.suppchan_2g_masks, chan);
			else
				setbit(sta->assoc_info.suppchan_5g_masks, chan);
			chan += chan_step;
		}
	}
}

void csm_parse_supp_opcalss(bss_table_t *bss,
	sta_table_t *sta, uint8_t *frm, uint8_t len)
{
	uint8_t i;
	uint8_t opclass;
	if (!bss || !sta || !frm || !len)
		return;

	/* Support Opclass IE included, reset and parse */
	memset(sta->assoc_info.suppopclass_masks, 0, OPCLASS_MASK_BYTES);

	for (i = 0; i < len; i++) {
		if (IEEE80211_DELIMITER_130 == frm[i]
			|| IEEE80211_DELIMITER_0 == frm[i])
			break;
		opclass = csm_get_global_opclass(bss->country_code, frm[i]);
		setbit(sta->assoc_info.suppopclass_masks, opclass);
	}
}

void csm_free_nonpref_chans(sta_table_t *sta)
{
	nonprefer_chan_t *nonpref = NULL;

	CSM_LOCK(sta);
	while (NULL != (nonpref = list_first_entry(
		&sta->assoc_info.nonpref_chan_lh, nonprefer_chan_t, lh))) {
		list_del(&nonpref->lh);

		if (nonpref->attr)
			CSM_FREE(nonpref->attr);
		CSM_FREE(nonpref);
	}
	CSM_UNLOCK(sta);
}

void csm_parse_mbo_nonpref_chan(sta_table_t *sta,
	uint8_t *frm, uint8_t len)
{
	nonprefer_chan_t *nonpref = NULL;
	uint32_t i;

	if (len < 3)
		return;

	nonpref = CSM_CALLOC(1, sizeof(nonprefer_chan_t));
	if (!nonpref)
		return;
	nonpref->attr = CSM_MALLOC(len + 2);
	if (!nonpref->attr) {
		CSM_FREE(nonpref);
		return;
	}
	nonpref->attr[0] = WIFI_MBO_ATTR_NONPREF_CHAN;
	nonpref->attr[1] = len;
	COPYMEM(nonpref->attr + 2, frm, len);

	nonpref->operating_class = *frm++;
	for (i = 0; i < len - 3; i++) {
		uint8_t chan = *frm++;
		nonpref->channels_included = 1;
		setbit(nonpref->channels, chan);
	}
	nonpref->perference = *frm++;
	nonpref->reason_code = *frm++;

	CSM_LOCK(sta);
	list_add_tail(&nonpref->lh,
		&sta->assoc_info.nonpref_chan_lh);
	CSM_UNLOCK(sta);
}

void csm_parse_mbo_cell_cap(sta_table_t *sta,
	uint8_t *frm, uint8_t len)
{
	if (len < 1)
		return;
	sta->mbo_cell_cap = *frm;
	sta->flag |= STATION_FLAG_MBO;
}

uint8_t *csm_store_ie(uint8_t *frm)
{
	uint16_t len = *(frm + 1) + 2;
	uint8_t *ie = CSM_MALLOC(len);
	if (ie)
		COPYMEM(ie, frm, len);
	return ie;
}

static uint8_t csm_add_one_sta_ie(uint8_t *ie,
	uint8_t *frm, uint32_t len)
{
	int ie_len = 0;
	if (ie) {
		ie_len = ie[1] + 2;
		if (len < ie_len)
			return -1;
		COPYMEM(frm, ie, ie_len);
	}
	return ie_len;
}

static int csm_add_mbo_oce_attr(uint8_t *attr, uint8_t **ie_len,
	uint8_t *frm, uint32_t len)
{
	int attr_len = 0, ie_hlen = 0;
	if (attr) {
		attr_len = attr[1] + 2;
		if (!(*ie_len) || *(*ie_len) + attr_len >= 256)
			ie_hlen = 2 + 4;	/* EID/LEN/OUI */
		if (len < ie_hlen + attr_len)
			return -1;
		if (ie_hlen) {
			*ie_len = frm + 1;
			frm += built_mbo_oce_ie(frm, 0);
		}
		COPYMEM(frm, attr, attr_len);
		/* update the LEN */
		*(*ie_len) = *(*ie_len) + attr_len;
	}
	return attr_len + ie_hlen;
}

static uint8_t csm_recombine_suppchan_ie(sta_table_t *sta,
	uint8_t *frm, uint32_t len)
{
	uint8_t *pos = frm;
	int i;

	if (len < 2)
	       return -1;

	/* recombine supported channel element with specified one channel tuple */
	if (sta->assoc_info.suppchan_2g_existed
		|| sta->assoc_info.suppchan_5g_existed) {
		*pos++ = IEEE80211_ELEMID_SUPPCHAN;
		pos++;
		for (i = FIRST_OPERATING_2G_CHAN; i <= LAST_OPERATING_2G_CHAN; i++) {
			if (len < pos - frm + 2)
				return -1;
			if (isset(sta->assoc_info.suppchan_2g_masks, i)) {
				*pos++ = i;
				*pos++ = 1;
			}
		}
		for (i = FIRST_OPERATING_5G_CHAN; i <= LAST_OPERATING_5G_CHAN; i++) {
			if (len < pos - frm + 2)
				return -1;
			if (isset(sta->assoc_info.suppchan_5g_masks, i)) {
				*pos++ = i;
				*pos++ = 1;
			}
		}
		frm[1] = pos - frm - 2;
	}

	return pos - frm;
}

int csm_build_sta_ies(sta_table_t *sta,
	uint8_t *frm, uint32_t len)
{
	uint8_t *pos = frm, *efrm = frm + len;
	int ret;
	uint8_t *ie_len = NULL;
	nonprefer_chan_t *nonpref;
#define CSM_ADD_ONE_STA_IE(_ie, _pos, _len) do {\
	ret = csm_add_one_sta_ie(_ie, _pos, _len);\
	if (ret < 0)	return -1;	\
	pos += ret; } while (0)
	ret = csm_recombine_suppchan_ie(sta, pos, efrm - pos);
	if (ret < 0)
		return -1;
	CSM_ADD_ONE_STA_IE(sta->assoc_info.supp_opclass_ie, pos, efrm - pos);
	CSM_ADD_ONE_STA_IE(sta->assoc_info.rm_enabled_ie, pos, efrm - pos);

	if (sta->mbo_cell_cap) {
		uint8_t cap_attr[] = { WIFI_MBO_ATTR_CELL_CAP, 1, 0 };
		cap_attr[2] = sta->mbo_cell_cap;
		ret = csm_add_mbo_oce_attr(cap_attr, &ie_len, pos, efrm - pos);
		if (ret < 0)
			return -1;
		pos += ret;
	}

	CSM_LOCK(sta);
	list_for_each_entry(nonpref, &sta->assoc_info.nonpref_chan_lh, lh) {
		ret = csm_add_mbo_oce_attr(nonpref->attr, &ie_len, pos, efrm - pos);
		if (ret < 0) {
			CSM_UNLOCK(sta);
			return -1;
		}
		pos += ret;
	}
	CSM_UNLOCK(sta);

	return pos - frm;
#undef CSM_ADD_ONE_STA_IE
}

static void csm_notify_ievent_to_logic(csmctx_t *csm,
	uint8_t *mdid, uint32_t event, void *param)
{
	int i;
	mobility_domain_t *md = csm_find_mobility_domain(csm, mdid);
	if (!md)
		return;

	for (i = 0; i < LOGIC_ROLE_MAX; i++) {
		if (!(md->instance_mask & (1 << i))
			|| !md->logic[i].plugin.splugin
			|| !md->logic[i].plugin.splugin->ops.notify_ievent)
			continue;

		md->logic[i].plugin.splugin->ops.notify_ievent(
			md->logic[i].instance, event, param);
	}
}

static mdid_table_t *csm_find_mdid(csmctx_t *csm, uint8_t *mdid)
{
	uint8_t pseudo_mac[ETH_ALEN];
	CSM_MAKE_PSEUDO_MAC(pseudo_mac, mdid);

	return (mdid_table_t *)stadb_sta_find(csm->mdid_db, pseudo_mac);
}

static mdid_table_t *csm_add_mdid(csmctx_t *csm, uint8_t *mdid, uint8_t *mac)
{
	mdid_table_t *mdid_tbl = NULL;
	uint8_t pseudo_mac[ETH_ALEN];
	CSM_MAKE_PSEUDO_MAC(pseudo_mac, mdid);

	mdid_tbl = (mdid_table_t *)stadb_sta_add(csm->mdid_db, pseudo_mac);
	if (mdid)
		memcpy(mdid_tbl->hessid, mac, ETH_ALEN);
	return mdid_tbl;
}

static inline void csm_notify_hessid_changed(csmctx_t *csm,
	uint8_t *mdid, uint8_t *mac)
{
	csm_notify_ievent_to_logic(csm, mdid,
		CSM_LOGIC_IEVENT_HESSID_UPDATE, NULL);
}

static void csm_hessid_reselect(csmctx_t *csm, mdid_table_t *mdid_tbl)
{
	uint32_t i;
	struct sta_sdb *db = csm->bss_db;
	bss_table_t *bss;

	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah;
		list_for_each_entry(stah, &db->stalh[i], lh) {
			bss = (bss_table_t *)stah;
			if (MDIDEQUAL(bss->mdid, CSM_MDID_FROM_PSEUDO_MAC(mdid_tbl->h.mac))) {
				COPYMAC(mdid_tbl->hessid, bss->h.mac);
				goto __end;
			}
		}
	}
__end:
	CSM_UNLOCK(db);

	csm_notify_hessid_changed(csm,
		CSM_MDID_FROM_PSEUDO_MAC(mdid_tbl->h.mac), mdid_tbl->hessid);
}

void csm_hessid_update(csmctx_t *csm, uint8_t *old_mdid,
	uint8_t *mdid, uint8_t *mac, csmpluginctx_t *ctx)
{
	mdid_table_t *mdid_tbl = NULL;
	if (!csm || !mdid || !mac)
		return;

	mdid_tbl = csm_find_mdid(csm, mdid);
	if (!mdid_tbl) {
		csm_add_mdid(csm, mdid, mac);
	} else {
		/* just save for slave(slave will update with NULL ctx) */
		if (!ctx && !MACEQUAL(mdid_tbl->hessid, mac)) {
			COPYMAC(mdid_tbl->hessid, mac);
			csm_notify_hessid_changed(csm, mdid, mac);
		}

		csm_put(&mdid_tbl->h);
	}

	/* If the old mdid's hessid is this bss, then should reselect the hessid */
	if (!old_mdid
		|| MDIDEQUAL(old_mdid, mdid))
		return;
	mdid_tbl = csm_find_mdid(csm, old_mdid);
	if (!mdid_tbl)
		return;
	if (MACEQUAL(mdid_tbl->hessid, mac))
		csm_hessid_reselect(csm, mdid_tbl);
	csm_put(&mdid_tbl->h);
}

static void csm_all_hessids_reselect(csmctx_t *csm)
{
	uint32_t i;
	struct sta_sdb *db = csm->mdid_db;
	struct list_head mdid_head;
	mdid_table_t *mdid_tbl;

	mdid_head = (struct list_head)LIST_HEAD_INIT(mdid_head);

	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah;
		list_for_each_entry(stah, &db->stalh[i], lh) {
			csm_get(stah);
			mdid_tbl = (mdid_table_t *)stah;
			list_add_tail(&mdid_tbl->lh, &mdid_head);
		}
	}
	CSM_UNLOCK(db);

	while (NULL != (mdid_tbl = list_first_entry(&mdid_head, mdid_table_t, lh))) {
		list_del(&mdid_tbl->lh);
		csm_hessid_reselect(csm, mdid_tbl);
		csm_put(&mdid_tbl->h);
	}
}

void csm_role_changed_callback(csmctx_t *csm,
	uint8_t o_role, uint8_t n_role)
{
	if (!csm)
		return;
	if (o_role == CSM_ROLE_SLAVE) {
		CSM_WARNING("Role changed from Slave, to reselect the hessid for all mdid");
		csm_all_hessids_reselect(csm);
	}
}

uint32_t csm_build_hessid_mdid_maps(void *ctx,
	uint8_t *buf, uint32_t space)
{
	uint32_t i, len = 0;
	csmctx_t *csm;
	struct sta_sdb *db;
	mdid_table_t *mdid_tbl;

	if (!ctx || !buf)
		return 0;

	csm = (csmctx_t *)(((csmpluginctx_t *)ctx)->csm);
	if (!csm)
		return 0;

	db = csm->mdid_db;
	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah;
		list_for_each_entry(stah, &db->stalh[i], lh) {
			mdid_tbl = (mdid_table_t *)stah;
			if (space >= ETH_ALEN + MDID_LEN) {
				COPYMDID(buf + len, CSM_MDID_FROM_PSEUDO_MAC(stah->mac));
				COPYMAC(buf + len + MDID_LEN, mdid_tbl->hessid);
				len += (ETH_ALEN + MDID_LEN);
			}
		}
	}
	CSM_UNLOCK(db);
	return len;
}

#define CSM_CHECK_FRAME_MATCH(_e, _s, _m, _l) ((_e)->subtype == (_s)	\
		&& (_e)->match_len <= (_l)	\
		&& (!(_m) || !(_l) || (0 == memcmp((_e)->match, (_m), (_e)->match_len))))

int csm_check_registrable_frame_matched(bss_table_t *bss,
	int is_rx, uint8_t subtype,
	const uint8_t *match, uint8_t match_len)
{
	struct list_head *frm_head = is_rx ?
		&bss->rxfrm_head : &bss->txfrm_head;
	frame_match_t *frm_match;

	list_for_each_entry(frm_match, frm_head, lh) {
		if (CSM_CHECK_FRAME_MATCH(frm_match, subtype, match, match_len))
			return 1;
	}
	return 0;
}

static frame_match_t *csm_init_registrable_frame(uint8_t subtype,
	uint8_t *match, uint8_t match_len)
{
	frame_match_t *frame_match;

	if (!match)
		match_len = 0;
	frame_match = CSM_MALLOC(sizeof(*frame_match) + match_len);
	if (!frame_match)
		return NULL;
	frame_match->subtype = subtype;
	frame_match->match_len = match_len;
	COPYMEM(frame_match->match, match, match_len);

	return frame_match;
}

void csm_update_registrable_frame(csmctx_t *csm,
	bss_table_t *bss, int is_rx, uint8_t subtype,
	uint8_t *match, uint8_t match_len)
{
	struct list_head *frm_head = is_rx ?
		&bss->rxfrm_head : &bss->txfrm_head;
	frame_match_t *frm_match, *entry, *tmp;

	if (csm_check_registrable_frame_matched(bss,
		is_rx, subtype, match, match_len))
		return;

	frm_match = csm_init_registrable_frame(subtype, match, match_len);
	if (!frm_match)
		return;

	list_for_each_entry_safe(entry, tmp, frm_head, lh) {
		if (CSM_CHECK_FRAME_MATCH(frm_match,
			entry->subtype, entry->match, entry->match_len)) {
			list_del(&entry->lh);
			CSM_FREE(entry);
		}
	}

	list_add_tail(&frm_match->lh, frm_head);
}

int csm_build_history_pkts(sta_table_t *sta,
	uint8_t *frm, uint32_t len)
{
	uint8_t *pos = frm, *efrm = frm + len;
	csm_averager *avg;
	uint32_t ind, nums = 0;

	if (!sta || !frm)
		return 0;

	avg = (csm_averager *)(sta->pkts_persec_averager);
	ind = CSM_AVERAGER_GET_PREV_IND(avg, avg->index);

	while ((pos + sizeof(uint32_t) <= efrm)
		&& nums++ < avg->nums) {
		*((uint32_t *)pos) = host_to_le32(avg->history[ind].value);
		pos += sizeof(uint32_t);
		ind = CSM_AVERAGER_GET_PREV_IND(avg, ind);
	}

	return pos - frm;
}

uint32_t csm_get_lower_pkts_nums(sta_table_t *sta,
	uint32_t threshold)
{
	csm_averager *avg;
	uint32_t ind, nums = 0;

	if (!sta)
		return 0;

	avg = (csm_averager *)(sta->pkts_persec_averager);
	ind = CSM_AVERAGER_GET_PREV_IND(avg, avg->index);

	while (avg->history[ind].value < threshold
		&& nums++ < avg->nums)
		ind = CSM_AVERAGER_GET_PREV_IND(avg, ind);

	return nums;
}

void csm_update_bss_into_radio(csmctx_t *csm, bss_table_t *bss, uint8_t *radio_id)
{
	radio_table_t *radio = NULL;
	if (!bss || !radio_id)
		return;

	if (bss->radio) {
		if (MACEQUAL(radio_id, bss->radio->h.mac))
			return;
		csm_remove_bss_from_radio(bss->radio, bss);
	}
	radio = csm_radio_find(csm->radio_db, radio_id);
	if (radio)
		csm_add_bss_into_radio(radio, bss);
}

opclass_entry_t *csm_find_radio_opclass_entry(radio_table_t *radio, uint8_t opclass)
{
	int i;
	for (i = 0; i < radio->opclass_nums; i++)
		if (radio->opclasses[i].global_opclass == opclass)
			return (radio->opclasses + i);
	return NULL;
}

static opclass_entry_t *csm_add_radio_opclass_entry(radio_table_t *radio, uint8_t opclass)
{
	opclass_entry_t *entry = NULL;
	if (radio->opclass_nums < CSM_CHAN_MAXNUM_PER_OPCLASS) {
		entry = &radio->opclasses[radio->opclass_nums++];
		entry->global_opclass = opclass;
	}
	return entry;
}

opclass_entry_t *csm_find_and_add_radio_opclass_entry(radio_table_t *radio, uint8_t opclass)
{
	opclass_entry_t *entry = csm_find_radio_opclass_entry(radio, opclass);
	if (!entry)
		entry = csm_add_radio_opclass_entry(radio, opclass);
	return entry;
}

chan_entry_t *csm_find_opclass_chan_entry(opclass_entry_t *opclass_info, uint8_t ch)
{
	int i;
	for (i = 0; i < opclass_info->chan_nums; i++)
		if (opclass_info->chans[i].chan == ch)
			return opclass_info->chans + i;
	return NULL;
}

static chan_entry_t *csm_add_opclass_chan_entry(opclass_entry_t *opclass_info, uint8_t ch)
{
	chan_entry_t *entry = NULL;
	if (opclass_info->chan_nums < CSM_CHAN_MAXNUM_PER_OPCLASS) {
		entry = &opclass_info->chans[opclass_info->chan_nums++];
		entry->chan = ch;
		/* init the newly entry to default value */
		entry->reason = CSM_CHAN_REASON_AVAILABLE;
		entry->preference = CSM_CHAN_MAX_PREF;
	}
	return entry;
}

chan_entry_t *csm_find_and_add_opclass_chan_entry(opclass_entry_t *opclass_info, uint8_t ch)
{
	chan_entry_t *entry = csm_find_opclass_chan_entry(opclass_info, ch);
	if (!entry)
		entry = csm_add_opclass_chan_entry(opclass_info, ch);
	return entry;
}

static inline uint16_t csmd_get_chan_set_cmd_len(void)
{
	return sizeof(tlv_t) + CSM_IE_LEN(ETH_ALEN)		/* TLVTYPE_RADIO_MAC */
		+ sizeof(tlv_t) + CSM_IE_LEN(4);		/* TLVTYPE_CH_CHANGE_INFO */
}

static uint8_t csm_get_max_txpower(csmctx_t *csm, uint8_t *rmac,
	uint8_t opcls, uint8_t ch, uint8_t bw)
{
	uint8_t max_txpower = 0;
	int i;
	struct sta_sdb *db = csm->radio_db;
	radio_table_t *radio = NULL;

	radio = csm_radio_find(db, rmac);
	if (!radio)
		goto __end;

	for (i = 0; i < radio->opclass_nums; i++) {
		if (!bw) {
			if (radio->opclasses[i].global_opclass == opcls)
				break;
		} else {
			if ((radio->opclasses[i].bandwidth == bw)
				&& csm_find_opclass_chan_entry(
					&radio->opclasses[i], ch))
				break;
		}
	}

	if (i < radio->opclass_nums)
		max_txpower = radio->opclasses[i].max_txpower;

__end:
	if (radio)
		csm_radio_put(radio);

	return max_txpower;
}

#define WFA_TESTING_WORKAROUND	1
static int csm_build_and_push_set_chan_cmd(csmctx_t *csm, uint8_t *rmac,
	uint8_t opcls, uint8_t ch, uint8_t txpwr, uint8_t max_txpwr)
{
	csmmsg_t *msg;
	csmmsgh_t *h;
	uint8_t *pos, buf[4];

	msg = csm_new_msg(CMD_SET_CHAN, CSM_RPE_VER(8), CSM_CODING_TLV,
			rmac, sizeof(csmmsgh_t) + csmd_get_chan_set_cmd_len());
	if (!msg)
		return -1;
	h = (csmmsgh_t *)csm_get_msg_body(msg);

	pos = h->payload;
	pos += csm_encap_tlv(pos, TLVTYPE_RADIO_MAC, rmac, ETH_ALEN);

	if (max_txpwr < txpwr)
		txpwr = max_txpwr;
	memset(buf, 0, sizeof(buf));
	buf[0] = opcls;
	buf[1] = ch;
	/* workaround for the max restriction of backoff by qtna driver.*/
#if WFA_TESTING_WORKAROUND
#define RADIO_BACKOFF_THRESHOLD_MIN	3
#define RADIO_BACKOFF_THRESHOLD_MAX	12
	uint8_t backoff = max_txpwr - txpwr;
	if (backoff <= RADIO_BACKOFF_THRESHOLD_MIN)
		backoff = 0;
	else if (backoff >= RADIO_BACKOFF_THRESHOLD_MAX)
		backoff = RADIO_BACKOFF_THRESHOLD_MAX;
	buf[2] = backoff;
#else
	buf[2] = max_txpwr - txpwr;
#endif
	buf[3] = max_txpwr;
	pos += csm_encap_tlv(pos, TLVTYPE_CH_CHANGE_INFO, buf, 4);

	return csm_push_cmd_ext(csm, NULL, msg);
}

int csm_set_radio_channel(void *ctx, uint8_t *rmac,
	uint8_t opcls, uint8_t ch, uint8_t txpwr, uint8_t bw)
{
	csmctx_t *csm;
	uint8_t max_txpwr = txpwr;

	if (!ctx || !rmac)
		return -1;

	csm = ((csmpluginctx_t *) ctx)->csm;
	max_txpwr = csm_get_max_txpower(csm, rmac, opcls, ch, bw);
	if (!max_txpwr)
		return -1;

	return csm_build_and_push_set_chan_cmd(csm, rmac, opcls, ch,
		txpwr, max_txpwr);
}

static inline uint16_t csm_get_intf_cfg_set_cmd_len(csm_intf_cfg_t *cfg)
{
	uint16_t len = sizeof(tlv_t) + CSM_IE_LEN(4);		/* TLVTYPE_INTF_FEATS */

	if (cfg->feat & cfg->feat_mask
		& CSM_INTF_FEAT_MONITOR)
		len += sizeof(tlv_t) + CSM_IE_LEN(4);		/* TLVTYPE_MONITOR_CFG */
	if (cfg->feat & cfg->feat_mask
		& CSM_INTF_FEAT_OMONITOR_ONDEMAND)
		len += sizeof(tlv_t) + CSM_IE_LEN(4);		/* TLVTYPE_OMONITOR_CFG */
	if (cfg->feat & cfg->feat_mask
		& CSM_INTF_FEAT_INTERWORKINGPROBES)
		len += sizeof(tlv_t) + CSM_IE_LEN(8);		/* TLVTYPE_INTERWORKINGPROBES_CFG */
	return len;
}

int csm_set_intf_cfg(void *ctx, uint8_t *bss_mac,
	csm_intf_cfg_t *cfg)
{
	csmctx_t *csm;
	csmmsg_t *msg;
	csmmsgh_t *h;
	uint16_t value[2];
	uint8_t value2[8];
	uint8_t *pos;

	if (!ctx || !bss_mac || !cfg)
		return -1;

	csm = ((csmpluginctx_t *) ctx)->csm;

	msg = csm_new_msg(CMD_SET_INTF_CFG, CSM_RPE_VER(8), CSM_CODING_TLV,
		bss_mac, sizeof(csmmsgh_t) + csm_get_intf_cfg_set_cmd_len(cfg));
	if (!msg)
		return -1;
	h = (csmmsgh_t *)csm_get_msg_body(msg);
	pos = h->payload;

	value[0] = host_to_le16(cfg->feat);
	value[1] = host_to_le16(cfg->feat_mask);
	pos += csm_encap_tlv(pos, TLVTYPE_INTF_FEATS, (uint8_t *)(value), 4);

	if (cfg->feat & cfg->feat_mask
		& CSM_INTF_FEAT_MONITOR) {
		value[0] = host_to_le16(cfg->mon_param.period);
		value[1] = cfg->mon_param.on_period;
		if (!cfg->mon_param.percent)
			value[1] |= 0x8000;
		value[1] = host_to_le16(value[1]);
		pos += csm_encap_tlv(pos, TLVTYPE_MONITOR_CFG, (uint8_t *)(value), 4);
	}
	if (cfg->feat & cfg->feat_mask
		& CSM_INTF_FEAT_OMONITOR_ONDEMAND) {
		pos += csm_encap_tlv(pos, TLVTYPE_OMONITOR_CFG,
				&cfg->mon_param.nac_chan, 1);
	}
	if (cfg->feat & cfg->feat_mask
		& CSM_INTF_FEAT_INTERWORKINGPROBES) {
		value2[0] = cfg->interw_param.interw_en;
		value2[1] = cfg->interw_param.an_type;
		memcpy(&value2[2], cfg->interw_param.hessid, ETH_ALEN);
		pos += csm_encap_tlv(pos, TLVTYPE_INTERWORKINGPROBES_CFG,
				(uint8_t *)(value2), 8);
	}
	return csm_push_cmd_ext(csm, NULL, msg);
}

static inline uint16_t csm_get_roam_cmd_len(void)
{
	return sizeof(tlv_t) + CSM_IE_LEN(ETH_ALEN)		/* TLVTYPE_BSSID */
		+ sizeof(tlv_t) + CSM_IE_LEN(3);		/* TLVTYPE_CHANNEL_BAND */
}

static int csm_build_and_push_roam_cmd(csmctx_t *csm, uint8_t *mac,
	uint8_t *target, uint8_t ch, uint8_t opclass)
{
	csmmsg_t *msg;
	csmmsgh_t *h;
	uint8_t value[4];
	uint8_t *pos;

	msg = csm_new_msg(CMD_ROAM, CSM_RPE_VER(8), CSM_CODING_TLV,
		mac, sizeof(csmmsgh_t) + csm_get_roam_cmd_len());
	if (!msg)
		return -1;
	h = (csmmsgh_t *)csm_get_msg_body(msg);
	pos = h->payload;

	pos += csm_encap_tlv(pos, TLVTYPE_BSSID, target, ETH_ALEN);
	value[0] = ch;
	value[1] = 0;
	value[2] = opclass;
	pos += csm_encap_tlv(pos, TLVTYPE_CHANNEL_BAND, value, 3);

	return csm_push_cmd_ext(csm, NULL, msg);
}

int csm_sta_roam(void *ctx, uint8_t *mac,
	uint8_t *target, uint8_t ch, uint8_t opclass)
{
	csmctx_t *csm;
	bss_table_t *bss;
	uint8_t is_sta = 0;

	if (!ctx || !mac || !target || !ch)
		return -1;

	csm = GET_CSMCTX(ctx);
	bss = csm_bss_find(csm->bss_db, mac);
	if (bss && bss->iftype == NODE_TYPE_STA)
		is_sta = 1;
	if (bss)
		csm_bss_put(bss);

	if (!is_sta) {
		CSM_WARNING("Interface %" MACFMT " is not STA mode", MACARG(mac));
		return -1;
	}

	return csm_build_and_push_roam_cmd(csm, mac, target, ch, opclass);
}
