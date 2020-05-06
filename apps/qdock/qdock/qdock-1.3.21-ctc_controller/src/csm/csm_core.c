/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <pthread.h>
#include "csm.h"


void *csm_new(size_t size)
{
	csmobj_t *obj = (csmobj_t *) calloc(1, size);
	if (obj) {
		CSM_LOCK_INIT(obj);
		return csm_get(obj);
	} else
		return NULL;
}

void *csm_get(void *o)
{
	csmobj_t *obj = o;
	CSM_LOCK(obj);
	obj->refcnt++;
	CSM_UNLOCK(obj);
	return obj;
}

void *csm_put(void *o)
{
	csmobj_t *obj = o;
	CSM_LOCK(obj);
	if (--(obj->refcnt) == 0) {
		if (unlikely(obj->free_data))
			obj->free_data(obj->data);
		CSM_UNLOCK(obj);
		CSM_FREE(obj);
		return NULL;
	} else {
		CSM_UNLOCK(obj);
		return obj;
	}
}

static uint32_t hash_256(uint8_t * mac)
{
	return (uint32_t) (mac[5]);
}

static uint32_t hash_16(uint8_t * mac)
{
	return (uint32_t) (mac[5] & 0xf);
}

static void
stadb_default_sta_copy(struct sta_sdb *db, stah_t * stah_dst,
		       stah_t * stah_src)
{
	memcpy(stah_dst + 1, stah_src + 1, db->sta_size - sizeof(stah_t));
}

#define NULLORFUNCTION(value, deffunc) ((value)?(value):(deffunc))

static struct sta_sdb *stadb_create(int hash_size, hash_func_t hash,
				    int sta_size,
				    sta_copy_func_t sta_copy, int max_size)
{
	struct sta_sdb *db =
	    CSM_NEW(sizeof(struct sta_sdb) +
		    sizeof(struct list_head) * hash_size);
	if (db) {
		int i;
		db->size = 0;
		db->max_size = max_size;
		db->hash_size = hash_size;
		db->hash = hash;
		db->sta_size = sta_size;
		db->sta_copy =
		    NULLORFUNCTION(sta_copy, stadb_default_sta_copy);
		for (i = 0; i < STA_SIGNAL_MAX; i++) {
			db->sta_signal_handler_lh[i] = (struct list_head)
			    LIST_HEAD_INIT(db->sta_signal_handler_lh[i]);
		}
		for (i = 0; i < hash_size; i++) {
			db->stalh[i] = (struct list_head)
			    LIST_HEAD_INIT(db->stalh[i]);
		}
	}
	return db;
}


int
stadb_connect_signal_unlock(struct sta_sdb *db, uint32_t signal,
			    int recall, sta_signal_func_t func,
			    void *ctx, void *param, sta_signal_release_func_t cb)
{
	int ret = 0;
	sta_signal_handler_t *sh = NULL;

	/* first find exist the same signal handler function in dlist
	 * if found, only free the old parameter point, update the new one */
	list_for_each_entry(sh, &db->sta_signal_handler_lh[signal], lh) {
		if (sh->func == func && sh->ctx == ctx) {
			if (sh->cb)
				sh->cb(sh->ctx, sh->param);
			sh->param = param;
			sh->cb = cb;
			goto do_recall;
		}
	}

	/* then if not found, create a new sta_signal_handler_t item,
	 * update it's new parameters and add it to the tail of dlist*/
	sh = CSM_CALLOC(1, sizeof(sta_signal_handler_t));
	if (sh) {
		sh->func = func;
		sh->ctx = ctx;
		sh->param = param;
		sh->cb = cb;
		list_add_tail(&sh->lh, &db->sta_signal_handler_lh[signal]);
	}

do_recall:
	if (recall) {
		int i;
		for (i = 0; i < db->hash_size; i++) {
			stah_t *stah;
			struct list_head *l = &db->stalh[i];
			list_for_each_entry(stah, l, lh) {
				func(stah, ctx, param);
			}
		}
	}

	return ret;
}

int stadb_process_signal_unlock(struct sta_sdb *db, stah_t * stah,
				uint32_t signal)
{
	int ret = 0;
	sta_signal_handler_t *sh;
	list_for_each_entry(sh, &db->sta_signal_handler_lh[signal], lh) {
		ret |= sh->func(stah, sh->ctx, sh->param);
	}
	return ret;
}

void stadb_disconnect_signal_all_handler_unlock(struct sta_sdb *db, uint32_t signal)
{
	sta_signal_handler_t *sh = NULL;
	sta_signal_handler_t *tmp = NULL;
	list_for_each_entry_safe(sh, tmp, &db->sta_signal_handler_lh[signal], lh) {
		if (sh->cb)
			sh->cb(sh->ctx, sh->param);
		list_del(&sh->lh);
		CSM_FREE(sh);
	}
}

stah_t *stadb_sta_find_unlock(struct sta_sdb *db, uint8_t * mac)
{
	stah_t *sta;
	uint32_t hash = db->hash(mac);
	struct list_head *lh = &db->stalh[hash];

	list_for_each_entry(sta, lh, lh) {
		if (MACEQUAL(sta->mac, mac)) {
			csm_get(sta);
			return sta;
		}
	}
	return NULL;
}

static backbone_info_t g_backbone_info;
static void csm_init_default_backbone(void)
{
	g_backbone_info.backbone_type = BACKBONE_TYPE_NONE;
	CLEARMAC(g_backbone_info.uplink_local);
	g_backbone_info.fixed_phyrate = 1000;
}

void csm_update_uplink_sta_type(csmctx_t *csm,
	uint8_t *uplink, uint8_t *old_uplink)
{
	sta_table_t *sta;

	if (MACADDR_EQ(uplink, old_uplink))
		return;

	/* sta with auto phyrate considered as REPEATER type */
	sta = (sta_table_t *)stadb_sta_find(csm->station_db, uplink);
	if (sta) {
		if (sta->node_type == NODE_TYPE_STA
			|| sta->node_type == NODE_TYPE_UNKNOW)
			sta->node_type = NODE_TYPE_REPEATER;
		csm_station_put(sta);
	}

	/* reset the REPEATER type to STA type if backbone link changed */
	sta = (sta_table_t *)stadb_sta_find(csm->station_db, old_uplink);
	if (sta) {
		if (sta->node_type == NODE_TYPE_REPEATER)
			sta->node_type = NODE_TYPE_STA;
		csm_station_put(sta);
	}
}

int csm_update_bss_backbone(void *ctx, uint8_t *uplink,
	uint32_t type, uint16_t fixed_phyrate)
{
	csmctx_t *csm = ((csmpluginctx_t *) ctx)->csm;
	stah_t *stah;
	bss_table_t *bss;
	struct sta_sdb *db = csm->bss_db;
	int i;
	sta_table_t *sta;

	CSM_LOCK(db);
	for (i = 0; i < db->hash_size; i++) {
		struct list_head *lh = &db->stalh[i];
		list_for_each_entry(stah, lh, lh) {
			bss = (bss_table_t *)stah;
			if (bss->flag & BSS_FLAG_REMOTE)
				continue;

			bss->backbone_info.backbone_type = type;
			COPYMAC(bss->backbone_info.uplink_local, uplink);
			bss->backbone_info.fixed_phyrate = fixed_phyrate;
		}
	}
	CSM_UNLOCK(db);

	if(fixed_phyrate) {
		sta = (sta_table_t *)stadb_sta_find_or_add(csm->station_db, uplink);
		if (sta) {
			sta->node_type = NODE_TYPE_NOTWIFI;
			CLEARMAC(sta->assoc_info.assoc_bssid);
			SET_FLAG(sta->flag, (STATION_FLAG_ASSOCIATED | STATION_FLAG_AUTHED));
			sta->assoc_info.avg_tx_phyrate = fixed_phyrate;
			sta->assoc_info.avg_rx_phyrate = fixed_phyrate;
			csm_station_put(sta);
		}
	}

	csm_update_uplink_sta_type(csm, uplink, g_backbone_info.uplink_local);

	g_backbone_info.backbone_type = type;
	COPYMAC(g_backbone_info.uplink_local, uplink);
	g_backbone_info.fixed_phyrate = fixed_phyrate;

	return 0;
}

static void stadb_try_ageout(struct sta_sdb *db)
{
	int agecnt = 3;
	stah_t *stah, *stah_safe, *candidate = NULL;
	int i;
	while ((agecnt > 0) && (db->size >= db->max_size)) {
		for (i = 0; i < db->hash_size; i++) {
			list_for_each_entry_safe(stah, stah_safe,
						 &db->stalh[i], lh) {
				if (db->ageout(stah, &candidate,
					       db->ageout_data)) {
					db->db_delete_sta(db, stah);
					agecnt--;
					if ((agecnt <= 0)
					    || (db->size < db->max_size))
						return;
				}
			}
		}
		if (candidate) {
			db->db_delete_sta(db, candidate);
			candidate = NULL;
			agecnt--;
		}
	}
}


static stah_t *stadb_sta_add_unlock(struct sta_sdb *db, uint8_t * mac)
{
	stah_t *sta = NULL;

	if (unlikely((db->max_size) && (db->size >= db->max_size))) {
		if ((db->ageout) && (db->db_delete_sta)) {
			stadb_try_ageout(db);
		} else {
			goto bail;
		}
	}
	sta = CSM_NEW(db->sta_size);
	if (sta) {
		uint32_t hash = db->hash(mac);
		COPYMAC(sta->mac, mac);
		csm_get(sta);
		stadb_process_signal_unlock(db, sta, STA_SIGNAL_ON_CREATE);
		db->size++;
		list_add_tail(&sta->lh, &db->stalh[hash]);
	}
      bail:
	return sta;
}

static stah_t *stadb_sta_add_unlock_ext1(struct sta_sdb *db, uint8_t * mac,
					 sta_early_init_func func,
					 void *data1, void *data2)
{
	stah_t *sta = NULL;

	if (unlikely((db->max_size) && (db->size >= db->max_size)))
		goto bail;
	sta = CSM_NEW(db->sta_size);
	if (sta) {
		uint32_t hash = db->hash(mac);
		COPYMAC(sta->mac, mac);
		csm_get(sta);
		if (func) {
			func(sta, data1, data2);
		}
		stadb_process_signal_unlock(db, sta, STA_SIGNAL_ON_CREATE);
		db->size++;
		list_add_tail(&sta->lh, &db->stalh[hash]);
	}
      bail:
	return sta;
}

int stadb_sta_delete_unlock(struct sta_sdb *db, stah_t * stah)
{
	list_del(&stah->lh);
	db->size--;
	stadb_process_signal_unlock(db, stah, STA_SIGNAL_ON_DESTROY);
	csm_put(stah);

	return 0;
}

int stadb_sta_delete_mac_unlock(struct sta_sdb *db, uint8_t * mac)
{
	stah_t *stah;
	uint32_t hash = db->hash(mac);
	struct list_head *lh = &db->stalh[hash];

	list_for_each_entry(stah, lh, lh) {
		if (MACEQUAL(stah->mac, mac)) {
			return stadb_sta_delete_unlock(db, stah);
		}
	}
	return -1;
}

/* this function should be called while
 * 1. dst is valid and dst->lock is locked
 * */
int stadb_fast_sync(struct sta_sdb *dst, struct sta_sdb *src)
{
	int i;
	CSM_LOCK(src);
	for (i = 0; i < src->hash_size; i++) {
		/* remove any deleted sta */
		struct list_head *dst_lh, *src_lh;
		stah_t *sta, *tmp;
		dst_lh = &dst->stalh[i];
		src_lh = &src->stalh[i];
		list_for_each_entry_safe(sta, tmp, dst_lh, lh) {
			if (stadb_sta_find_unlock(src, sta->mac) == NULL) {
				list_del(&sta->lh);
				stadb_process_signal_unlock(src, sta,
							    STA_SIGNAL_ON_DESTROY);
				csm_put(sta);
			}
		}
		list_for_each_entry(sta, src_lh, lh) {
			if (((tmp =
			      stadb_sta_find_unlock(dst,
						    sta->mac))) == NULL) {
				tmp = stadb_sta_add_unlock(dst, sta->mac);
			}
			if (tmp) {
				if (sta->age != tmp->age) {
					CSM_LOCK(sta);
					dst->sta_copy(dst, tmp, sta);
					tmp->age = sta->age;
					CSM_UNLOCK(sta);
				}
			}
		}

	}

	CSM_UNLOCK(src);
	return 0;
}


stah_t *stadb_sta_add(struct sta_sdb *db, uint8_t * mac)
{
	stah_t *sta;

	CSM_LOCK(db);
	sta = stadb_sta_add_unlock(db, mac);
	CSM_UNLOCK(db);
	return sta;
}

stah_t *stadb_sta_find(struct sta_sdb * db, uint8_t * mac)
{
	stah_t *sta;

	CSM_LOCK(db);
	sta = stadb_sta_find_unlock(db, mac);
	CSM_UNLOCK(db);

	return sta;
}

stah_t *stadb_sta_find_or_add(struct sta_sdb * db, uint8_t * mac)
{
	stah_t *sta;

	CSM_LOCK(db);
	sta = stadb_sta_find_unlock(db, mac);
	if (sta == NULL)
		sta = stadb_sta_add_unlock(db, mac);
	CSM_UNLOCK(db);
	return sta;
}

stah_t *stadb_sta_find_or_add_ext1(struct sta_sdb * db, uint8_t * mac,
				   sta_early_init_func func, void *data1,
				   void *data2)
{
	stah_t *sta;

	CSM_LOCK(db);
	sta = stadb_sta_find_unlock(db, mac);
	if (sta == NULL)
		sta =
		    stadb_sta_add_unlock_ext1(db, mac, func, data1, data2);
	CSM_UNLOCK(db);
	return sta;
}

int stadb_sta_delete(struct sta_sdb *db, uint8_t * mac)
{
	int ret;
	CSM_LOCK(db);
	ret = stadb_sta_delete_mac_unlock(db, mac);
	CSM_UNLOCK(db);
	return ret;
}

void stadb_delete(struct sta_sdb *db)
{
	uint32_t signal = 0;
	CSM_LOCK(db);
	for (signal = STA_SIGNAL_ON_CREATE; signal < STA_SIGNAL_MAX; signal++)
		stadb_disconnect_signal_all_handler_unlock(db, signal);
	CSM_UNLOCK(db);

	CSM_FREE(db);
}

mobility_domain_t *csm_find_mobility_domain(csmctx_t * csm, uint8_t * mdid)
{
	mobility_domain_t *ctx = csm->mds;
	while (ctx) {
		if (MDIDEQUAL(mdid, ctx->mdid))
			break;
		ctx = ctx->next;
	}
	return ctx;
}

static mobility_domain_t *csm_create_mobility_domain(csmctx_t * csm,
						     uint8_t * mdid)
{
	mobility_domain_t *ctx = CSM_NEW(sizeof(mobility_domain_t));
	if (ctx) {
		COPYMDID(ctx->mdid, mdid);
		INSERT_LIST(csm->mds, ctx);
	}
	return ctx;
}

void csm_attach_logic_to_mobility_domain(csmctx_t * csm, const char
					 *logic_name, uint8_t * mdid, void
					 *init_param)
{
	struct csm_logic_plugin *splugin = (struct csm_logic_plugin *)
	    csm_find_plugin(csm->logic_plugins,
			    logic_name);
	mobility_domain_t *md = NULL;

	if ((splugin)) {
		if (((md = csm_find_mobility_domain(csm, mdid)) == NULL))
			md = csm_create_mobility_domain(csm, mdid);
		if (md) {
			CSM_LOCK(md);
			md->pluginctx.csm = csm;
			md->pluginctx.type = CSM_PLUGIN_TYPE_LOGIC;
			md->pluginctx.init_param = init_param;
			md->logic[splugin->type].plugin.splugin = splugin;

			md->logic[splugin->type].instance =
			    LOAD_PLUGIN(splugin, md);
			if (md->logic[splugin->type].instance) {
				md->instance_mask |= (1 << splugin->type);
				CSM_INFO("Mobility domain:[%" MDIDFMT
					 "] created with logic:%s attached.",
					 MDIDARG(md->mdid), logic_name);
			}
			CSM_UNLOCK(md);
			md->pluginctx.ready = 1;
		}

	}
}


void csm_attach_drv(csmctx_t * csm, const char *drv_name, void *init_param)
{
	struct csm_drv_plugin *dplugin =
	    (struct csm_drv_plugin *) csm_find_plugin(csm->drv_plugins,
						      drv_name);

	if (dplugin) {
		drvctx_t *drv = CSM_NEW(sizeof(drvctx_t));
		if (drv) {
			CSM_LOCK(drv);
			drv->pluginctx.csm = csm;
			drv->pluginctx.type = CSM_PLUGIN_TYPE_DRIVER;
			drv->pluginctx.init_param = init_param;
			drv->drv.plugin.dplugin = dplugin;

			drv->drv.instance = LOAD_PLUGIN(dplugin, drv);
			if (drv->drv.instance) {
				CSM_INFO("driver:%s loaded.", drv_name);
				CSM_UNLOCK(drv);
				drv->pluginctx.ready = 1;
				INSERT_LIST(csm->drvs, drv);
			} else {
				CSM_NOTICE("driver %s failed to load.", drv_name);
				CSM_UNLOCK(drv);
				csm_put(drv);
			}
		}
	}
}

void csm_attach_comm(csmctx_t * csm,
		     const char *comm_name, void *init_param)
{
	struct csm_comm_plugin *cplugin =
	    (struct csm_comm_plugin *) csm_find_plugin(csm->comm_plugins,
						       comm_name);

	if (cplugin) {
		commctx_t *comm = CSM_NEW(sizeof(commctx_t));
		if (comm) {
			CSM_LOCK(comm);
			comm->pluginctx.csm = csm;
			comm->pluginctx.type = CSM_PLUGIN_TYPE_COMM;
			comm->pluginctx.init_param = init_param;
			comm->comm.plugin.cplugin = cplugin;

			comm->comm.instance = LOAD_PLUGIN(cplugin, comm);
			if (comm->comm.instance) {
				CSM_INFO("communication:%s loaded.",
					 comm_name);

				CSM_UNLOCK(comm);
				comm->pluginctx.ready = 1;
				INSERT_LIST(csm->comms, comm);
			} else {
				CSM_UNLOCK(comm);
				csm_put(comm);
			}
		}
	}
}

void csm_attach_misc(csmctx_t * csm,
		     const char *misc_name, void *init_param)
{
	struct csm_misc_plugin *mplugin =
	    (struct csm_misc_plugin *) csm_find_plugin(csm->misc_plugins,
						       misc_name);

	if (mplugin) {
		miscctx_t *misc = CSM_NEW(sizeof(miscctx_t));
		if (misc) {
			CSM_LOCK(misc);
			misc->pluginctx.csm = csm;
			misc->pluginctx.type = CSM_PLUGIN_TYPE_MISC;
			misc->pluginctx.init_param = init_param;
			misc->misc.plugin.mplugin = mplugin;
			misc->misc.instance = LOAD_PLUGIN(mplugin, misc);
			if (misc->misc.instance) {
				CSM_INFO("misc:%s loaded.", misc_name);
				CSM_UNLOCK(misc);
				misc->pluginctx.ready = 1;
				INSERT_LIST(csm->miscs, misc);
			} else {
				CSM_UNLOCK(misc);
				csm_put(misc);
			}
		}
	}
}

static int csm_bss_init(stah_t * h, void *data1, void *data2)
{
	bss_table_t *bss = (bss_table_t *) h;
	bss->fat = 1000;
	bss->backbone_info.backbone_type = g_backbone_info.backbone_type;
	COPYMAC(bss->backbone_info.uplink_local, g_backbone_info.uplink_local);
	bss->backbone_info.fixed_phyrate = g_backbone_info.fixed_phyrate;
	bss->txfrm_head = (struct list_head)LIST_HEAD_INIT(bss->txfrm_head);
	bss->rxfrm_head = (struct list_head)LIST_HEAD_INIT(bss->rxfrm_head);
	bss->spdia_sta_head= (struct list_head)LIST_HEAD_INIT(bss->spdia_sta_head);

	return 0;
}

static int csm_station_init(stah_t * h, void *data1, void *data2)
{
	sta_table_t *sta = (sta_table_t *) h;
	sta->seen_mdid_lh =
	    (struct list_head) LIST_HEAD_INIT(sta->seen_mdid_lh);
	sta->assoc_info.nonpref_chan_lh =
		(struct list_head) LIST_HEAD_INIT(sta->assoc_info.nonpref_chan_lh);
	sta->tx_phyrate_averager = csm_averager_create(AVERAGER_SHIFT);
	sta->rx_phyrate_averager = csm_averager_create(AVERAGER_SHIFT);
	sta->rssi_averager = csm_averager_create(AVERAGER_SHIFT);
	sta->pkts_persec_averager = csm_averager_create(AVERAGER_SHIFT);
	sta->node_type = NODE_TYPE_UNKNOW;
	return 0;
}

static int csm_radio_init(stah_t *h, void *data1, void *data2)
{
	radio_table_t *radio = (radio_table_t *)h;

	radio->bss_head =
		(struct list_head) LIST_HEAD_INIT(radio->bss_head);
	return 0;
}

static inline void
csm_seen_bssid_copy(struct list_head *dlh, struct list_head *slh)
{
	sta_seen_bssid_t *d, *s;
	d = list_entry(dlh->next, typeof(*d), lh);
	list_for_each_entry(s, slh, lh) {
		if (&d->lh == dlh) {
			d = CSM_CALLOC(1, sizeof(sta_seen_bssid_t));
			if (d == NULL) {
				return;
			}
			list_add_tail(&d->lh, dlh);
		}
		COPYMAC(d->bssid, s->bssid);
		d->last_rssi = s->last_rssi;
		d->last_ts = s->last_ts;
		d = list_entry(d->lh.next, typeof(*d), lh);
	}

	while (&d->lh != dlh) {
		s = list_entry(d->lh.next, typeof(*d), lh);
		CSM_FREE(d);
		d = s;
	}
}

static void
csm_station_copy(struct sta_sdb *db, stah_t * dst, stah_t * src)
{
	sta_table_t *d = (sta_table_t *) dst;
	sta_table_t *s = (sta_table_t *) src;
	int i;

	memcpy(d->MDID, s->MDID, MDID_LEN);
	d->assoc_info = s->assoc_info;
	for (i = 0; i < BAND_MAX; i++) {
		d->sta_band_info[i] = s->sta_band_info[i];
	}
	d->band_mask = s->band_mask;
	d->last_band = s->last_band;
	d->last_channel = s->last_channel;
	d->flag = s->flag;

	csm_seen_bssid_copy(&d->seen_mdid_lh, &s->seen_mdid_lh);
}

static int csm_bss_destroy(stah_t * stah, void *data1, void *data2)
{
    bss_table_t *bss = (bss_table_t *)stah;
    struct list_head *frm_head;
    frame_match_t *entry, *tmp;

    frm_head = &bss->rxfrm_head;
    list_for_each_entry_safe(entry, tmp, frm_head, lh) {
        list_del(&entry->lh);
        CSM_FREE(entry);
    }
    frm_head = &bss->txfrm_head;
    list_for_each_entry_safe(entry, tmp, frm_head, lh) {
        list_del(&entry->lh);
        CSM_FREE(entry);
    }
    return 0;
}

static int csm_station_destroy(stah_t * stah, void *data1, void *data2)
{
	sta_table_t *sta = (sta_table_t *) stah;
	sta_seen_bssid_t *stasbssid, *tmpb;
	sta_seen_mdid_t *stasmdid, *tmpm;

	list_for_each_entry_safe(stasmdid, tmpm, &sta->seen_mdid_lh, lh) {
		list_for_each_entry_safe(stasbssid, tmpb,
					 &stasmdid->seen_bssid_lh, lh) {
			list_del(&stasbssid->lh);
			CSM_FREE(stasbssid);
		}
		list_del(&stasmdid->lh);
		CSM_FREE(stasmdid);
	}
	csm_averager_destroy(sta->tx_phyrate_averager);
	csm_averager_destroy(sta->rx_phyrate_averager);
	csm_averager_destroy(sta->rssi_averager);
	csm_averager_destroy(sta->pkts_persec_averager);

	csm_reset_assoc_info(sta);

	return 0;
}

static int csm_radio_destroy(stah_t * stah, void *data1, void *data2)
{
	radio_table_t *radio = (radio_table_t *)stah;
	csmctx_t *csm = (csmctx_t *)data1;
	bss_table_t *bss, *tmp;

	list_for_each_entry_safe(bss, tmp, &radio->bss_head, radio_lh)
		csm_bss_delete(csm, bss);

	return 0;
}

int csm_create_station_db(csmctx_t * csm, int max_size)
{
	int ret = 0;
	struct sta_sdb *db, *snapshot;


	db = stadb_create(HASH_SIZE_256, hash_256, sizeof(sta_table_t),
			  csm_station_copy, max_size);
	if (db == NULL) {
		ret = -1;
		goto fail;
	}
	CSM_LOCK(db);
	db->ageout_data = &csm->sta_ageout_config;
	db->ageout = csm_station_age_out;
	db->db_delete_sta = stadb_sta_delete_unlock;
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_CREATE, 0,
				    csm_station_init, NULL, NULL, NULL);
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_DESTROY, 0,
				    csm_station_destroy, NULL, NULL, NULL);
	CSM_UNLOCK(db);

	snapshot =
	    stadb_create(db->hash_size, db->hash, db->sta_size,
			 db->sta_copy, 0);
	if (snapshot == NULL) {
		ret = -1;
		goto fail;
	}
	CSM_LOCK(snapshot);
	stadb_connect_signal_unlock(snapshot, STA_SIGNAL_ON_CREATE, 0,
				    csm_station_init, NULL, NULL, NULL);
	stadb_connect_signal_unlock(snapshot, STA_SIGNAL_ON_DESTROY, 0,
				    csm_station_destroy, NULL, NULL, NULL);
	CSM_UNLOCK(snapshot);
	csm->station_db = db;
	csm->station_db_snapshot = snapshot;
	CSM_INFO("Create station database with max size = %d", max_size);
      fail:
	return ret;
}

static void csm_flush_remote_bss(void *data1, void *data2)
{
	csmctx_t *csm = (csmctx_t *)data1;
	struct sta_sdb *db = csm->bss_db;
	int i;

	CSM_LOCK(db);

	for (i = 0; i < db->hash_size; i++) {
		stah_t *stah, *tmp;
		bss_table_t *bss;
		list_for_each_entry_safe(stah, tmp, &db->stalh[i], lh) {
			bss = (bss_table_t *)stah;
			if ((bss->flag & BSS_FLAG_REMOTE)
				&& csm_get_age(bss->last_fat) >
					csm->sta_ageout_config.age_timeout)
				csm_bss_delete(csm, bss);
		}
	}

	CSM_UNLOCK(db);
}

int csm_create_bss_db(csmctx_t * csm, int max_size)
{
	struct sta_sdb *db = NULL, *snapshot = NULL, *devid_db = NULL;
	struct sta_sdb *mdid_db = NULL;

	db = stadb_create(HASH_SIZE_16, hash_16, sizeof(bss_table_t), NULL,
			  max_size);
	if (db == NULL) {
		goto fail;
	}
	CSM_LOCK(db);
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_CREATE, 0,
				    csm_bss_init, NULL, NULL, NULL);
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_DESTROY, 0,
				    csm_bss_destroy, NULL, NULL, NULL);
	CSM_UNLOCK(db);

	snapshot =
	    stadb_create(db->hash_size, db->hash, db->sta_size,
			 db->sta_copy, 0);
	if (snapshot == NULL) {
		goto fail;
	}
	CSM_LOCK(snapshot);
	stadb_connect_signal_unlock(snapshot, STA_SIGNAL_ON_CREATE, 0,
				    csm_bss_init, NULL, NULL, NULL);
	CSM_UNLOCK(snapshot);

	devid_db = stadb_create(HASH_SIZE_16, hash_16, sizeof(devid_table_t), NULL,
			  max_size);
	if (devid_db == NULL)
		goto fail;

	mdid_db = stadb_create(HASH_SIZE_16, hash_16, sizeof(mdid_table_t), NULL,
			  max_size);
	if (mdid_db == NULL)
		goto fail;

	csm->bss_db = db;
	csm->bss_db_snapshot = snapshot;
	csm->devid_db = devid_db;
	csm->mdid_db = mdid_db;

	csm_timer_register(csm, csm->sta_ageout_config.age_timeout * 1000 / 2,
		csm_flush_remote_bss, csm, NULL, 1);

	CSM_INFO("Create BSS database with max size = %d", max_size);

	return 0;

      fail:
	CSM_ERROR("Create BSS database with max size = %d fail", max_size);
	if (db)
		csm_put(db);
	if (snapshot)
		csm_put(snapshot);
	if (devid_db)
		csm_put(devid_db);
/*	if (mdid_db)
		csm_put(mdid_db);
*/
	return -1;
}

int csm_create_radio_db(csmctx_t *csm, int max_size)
{
	struct sta_sdb *db = NULL;

	db = stadb_create(HASH_SIZE_16, hash_16, sizeof(radio_table_t), NULL,
			max_size);
	if (db == NULL)
		goto fail;

	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_CREATE, 0,
		csm_radio_init, csm, NULL, NULL);
	stadb_connect_signal_unlock(db, STA_SIGNAL_ON_DESTROY, 0,
		csm_radio_destroy, csm, NULL, NULL);

	csm->radio_db = db;

	CSM_INFO("Create Radio database with max size = %d", max_size);

	return 0;

fail:
	CSM_ERROR("Create Radio database with max size = %d fail", max_size);
	return -1;
}

char *csm_get_next_plugin_name(DIR * dir)
{
	char *name = NULL;
	struct dirent *dirent;
	while ((dirent = readdir(dir))) {
		if (dirent->d_type == DT_REG) {
			name = dirent->d_name;
			break;
		}
	};
	return name;
}

int csm_unix_sock_open(const char *name)
{
	int sd;
	struct sockaddr_un addr;

	sd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0)
		return -1;

	unlink(name);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, name, sizeof(addr.sun_path) - 1);
	if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sd);
		return -1;
	}

	return sd;
}

int g_csm_log_handle = -1;

csmctx_t *csm_init()
{
	csmctx_t *ctx = CSM_CALLOC(1, sizeof(csmctx_t));

	if (ctx) {
		csm_log_init();
		g_csm_log_handle =
		    csm_log_register(COLORFUL_STR(COLOR_PURPLE, "CSM "),
				     LOG_INFO);
		pthread_mutex_init(&ctx->lock, NULL);
		csm_timer_init(ctx);
		ctx->sta_ageout_config.age_timeout = 120;	/* 2 min */
	}
	csm_init_default_backbone();
	return ctx;
}
