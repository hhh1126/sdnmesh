/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <pthread.h>
#include "csm.h"

#define list_first(list, type, member) \
	(list_empty((list)) ? NULL : \
	 list_entry((list)->next, type, member))


static inline int time_before(struct timeval *a, struct timeval *b)
{
	return (a->tv_sec < b->tv_sec) ||
	    (a->tv_sec == b->tv_sec && a->tv_usec < b->tv_usec);
}

static inline void time_sub(struct timeval *a, struct timeval *b,
			    struct timeval *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_usec = a->tv_usec - b->tv_usec;
	if (res->tv_usec < 0) {
		res->tv_sec--;
		res->tv_usec += 1000000;
	}
}

static inline void time_add(struct timeval *a, struct timeval *b,
			    struct timeval *res)
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_usec = a->tv_usec + b->tv_usec;
	if (res->tv_usec >= 1000000) {
		res->tv_sec++;
		res->tv_usec -= 1000000;
	}
}


static void csm_timer_remove_unlock(void *ctx, csm_timer_t * timer)
{
	list_del(&timer->lh);
	CSM_FREE(timer);
}

int csm_timer_cancel(void *ctx, csm_timer_func_t func, void *data1,
		     void *data2)
{
	csmctx_t *csm = (csmctx_t *)ctx;
	csmtimerctx_t *tctx = &csm->timerctx;
	struct list_head *lh = &tctx->tlist;
	csm_timer_t *timer, *prev;
	int removed = 0;

	pthread_mutex_lock(&tctx->lock);
	list_for_each_entry_safe(timer, prev, lh, lh) {
		if (timer->func == func && timer->data1 == data1
		    && timer->data2 == data2) {
			csm_timer_remove_unlock(ctx, timer);
			++removed;
		}
	}
	pthread_mutex_unlock(&tctx->lock);
	return removed;
}

int csm_timer_register(void *ctx, uint32_t msecs,
		       csm_timer_func_t func, void *data1, void *data2,
		       int repeat)
{
	csmctx_t *csm = (csmctx_t *)ctx;
	csmtimerctx_t *tctx = &csm->timerctx;
	struct list_head *lh;
	csm_timer_t *timer, *tmp;
	struct timeval interval, now;

	if (!tctx || !func)
		return -1;

	timer = CSM_CALLOC(1, sizeof(csm_timer_t));
	if (timer == NULL)
		return -1;

	if (gettimeofday(&now, NULL) < 0) {
		CSM_FREE(timer);
		return -1;
	}

	interval.tv_sec = msecs / 1000;
	interval.tv_usec = (msecs % 1000) * 1000;

	time_add(&now, &interval, &timer->timeout);
	timer->data1 = data1;
	timer->data2 = data2;
	timer->func = func;
	if (repeat)
		timer->interval = msecs;

	csm_timer_cancel(ctx, func, data1, data2);

	lh = &tctx->tlist;
	pthread_mutex_lock(&tctx->lock);
	list_for_each_entry(tmp, lh, lh) {
		if (time_before(&timer->timeout, &tmp->timeout)) {
			__list_add(&timer->lh, tmp->lh.prev, &tmp->lh);
			goto bail;
		}
	}

	list_add_tail(&timer->lh, &csm->timerctx.tlist);
      bail:
	pthread_mutex_unlock(&tctx->lock);
	pthread_cond_signal(&csm->timerctx.wait);
	return 0;
}


static int csm_timer_process(csmtimerctx_t * tctx)
{
	struct timespec timeout;
	struct timeval now;
	csm_timer_t *timer;
	void *data1, *data2;
	uint32_t msecs;
	csm_timer_func_t func;
	csmctx_t *ctx = container_of(tctx, csmctx_t, timerctx);

	pthread_mutex_lock(&tctx->lock);
	timer = list_first(&tctx->tlist, csm_timer_t, lh);
	if (timer) {
		timeout.tv_sec = timer->timeout.tv_sec;
		timeout.tv_nsec = timer->timeout.tv_usec * 1000;
	} else {
		if (gettimeofday(&now, NULL) >= 0) {
			timeout.tv_sec = now.tv_sec + 1;
			timeout.tv_nsec = now.tv_usec * 1000;
		} else {
			timeout.tv_sec = 0;
			timeout.tv_nsec = 0;
		}
	}
	pthread_cond_timedwait(&tctx->wait, &tctx->lock, &timeout);
	timer = list_first(&tctx->tlist, csm_timer_t, lh);

	if (timer) {
		gettimeofday(&now, NULL);
		if (!time_before(&now, &timer->timeout)) {
			data1 = timer->data1;
			data2 = timer->data2;
			func = timer->func;
			msecs = timer->interval;
			csm_timer_remove_unlock(ctx, timer);
			pthread_mutex_unlock(&tctx->lock);
			if (msecs) {
				csm_timer_register(ctx, msecs, func,
						   data1, data2, 1);
			}
			func(data1, data2);
			return 0;

		}
	}
	pthread_mutex_unlock(&tctx->lock);
	return 0;

}

static void *csm_timer_background_thread(void *ctx)
{
	csmtimerctx_t *tctx = (csmtimerctx_t *) ctx;

	while (tctx->running) {
		csm_timer_process(tctx);
	}
	return NULL;
}


int csm_timer_init(csmctx_t * ctx)
{
	csmtimerctx_t *tctx = &ctx->timerctx;

	pthread_mutex_init(&tctx->lock, NULL);
	pthread_cond_init(&tctx->wait, NULL);
	tctx->tlist = (struct list_head) LIST_HEAD_INIT(tctx->tlist);
	tctx->running = 1;

	pthread_create(&tctx->thread, NULL, csm_timer_background_thread,
		       tctx);
	return 0;

}
