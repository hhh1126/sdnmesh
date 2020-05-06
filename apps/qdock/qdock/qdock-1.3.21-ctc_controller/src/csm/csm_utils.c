/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include "csm_utils.h"

#define CSMPREFIX "csm"

#ifdef MEMORY_DEBUG
#include <pthread.h>
#define MDBG_LOCK pthread_mutex_lock(&csm_dbg_mem.lock)
#define MDBG_UNLOCK pthread_mutex_unlock(&csm_dbg_mem.lock)
#define MDBG_MAGIC 0x12345678
#define MDBG_FREE_MAGIC 0x11111111
#define DBGPREFIX "[csmdbg]: "
typedef struct {
	uint32_t magic;
	uint32_t age;
	struct list_head lh;
	size_t size;
	char *file;
	int line;
} csm_mem_ctl_t;


typedef struct {
	char *file;
	int line;
	struct list_head lh;
	uint32_t num_max_last;
	uint32_t num_max;
	uint32_t num;
} csm_mem_history_t;

static struct csm_debug_memory {
	pthread_mutex_t lock;
	struct list_head m;
	struct list_head history;
	size_t maxsize;
	size_t size;
	uint32_t maxnum;
	uint32_t num;
	uint32_t age;
} csm_dbg_mem = {
.lock = PTHREAD_MUTEX_INITIALIZER,
		.m = (struct list_head) LIST_HEAD_INIT(csm_dbg_mem.m),
		.history = (struct list_head) LIST_HEAD_INIT(csm_dbg_mem.history),
		.maxsize = 0,
		.size = 0,
		.maxnum = 0,
		.num = 0,
		.age = 0,
		};

static void csm_debug_add_history(char *file, int line)
{
	csm_mem_history_t *ph;

	list_for_each_entry(ph, &csm_dbg_mem.history, lh) {
		if ((!strcmp(ph->file, file)) && (ph->line==line)) {
			if ((++ph->num)>ph->num_max)
				ph->num_max = ph->num;
			return;
		}
	}
	ph = calloc(sizeof(csm_mem_history_t),1);
	if (ph) {
		ph->file = file;
		ph->line = line;
		ph->num = ph->num_max = 1;
		list_add_tail(&ph->lh, &csm_dbg_mem.history);
	}
}

static void csm_debug_remove_history(char *file, int line)
{
	csm_mem_history_t *ph;

	list_for_each_entry(ph, &csm_dbg_mem.history, lh) {
		if ((!strcmp(ph->file, file)) && (ph->line==line)) {
			ph->num--;
			return;
		}
	}
	printf(DBGPREFIX "[%s:%d] history not exist!\n", file, line);
}

void *csm_debug_malloc(size_t size, char *file, int line)
{
	csm_mem_ctl_t *ptr;
	size_t tsize = size + sizeof(csm_mem_ctl_t);

	ptr = malloc(tsize);
	if (ptr) {
		ptr->magic = MDBG_MAGIC;
		ptr->size = size;
		ptr->file = file;
		ptr->line = line;
		MDBG_LOCK;
		ptr->age = (csm_dbg_mem.age++);
		list_add_tail(&ptr->lh, &csm_dbg_mem.m);
		csm_debug_add_history(file, line);
		csm_dbg_mem.size += size;
		csm_dbg_mem.num++;
		if (csm_dbg_mem.size > csm_dbg_mem.maxsize) {
			csm_dbg_mem.maxsize = csm_dbg_mem.size;
			printf(DBGPREFIX "[%s:%d] maxsize: %zd\n", file,
			       line, csm_dbg_mem.maxsize);
		}
		if (csm_dbg_mem.num > csm_dbg_mem.maxnum) {
			csm_dbg_mem.maxnum = csm_dbg_mem.num;
			printf(DBGPREFIX "[%s:%d] maxnum: %d\n", file,
			       line, csm_dbg_mem.maxnum);
		}
		MDBG_UNLOCK;
		ptr++;
	}
	return (void *) ptr;
}


void *csm_debug_calloc(size_t num, size_t size, char *file, int line)
{
	size_t tsize = size * num;
	void *ptr = csm_debug_malloc(tsize, file, line);
	if (ptr) {
		memset(ptr, 0, tsize);
	}
	return ptr;
}

void csm_debug_free(void *p, char *file, int line)
{
	if (p) {
		csm_mem_ctl_t *ptr = (csm_mem_ctl_t *) p;
		ptr--;
		MDBG_LOCK;
		if (ptr->magic != MDBG_MAGIC) {
			printf(DBGPREFIX "[%s:%d] wild pointer %p\n", file,
			       line, p);
			MDBG_UNLOCK;
			return;
		}
		list_del(&ptr->lh);
		csm_dbg_mem.size -= ptr->size;
		csm_dbg_mem.num--;
		csm_debug_remove_history(ptr->file, ptr->line);
		ptr->magic = MDBG_FREE_MAGIC;
		MDBG_UNLOCK;

		free(ptr);

	} else
		printf(DBGPREFIX "[%s:%d] null pointer\n", file, line);
}

extern void *csm_get(void *o);
void *csm_debug_new(size_t size, char *file, int line)
{
	csmobj_t *obj = (csmobj_t *) csm_debug_calloc(1, size, file, line);
	if (obj) {
		pthread_mutex_init(&obj->lock, NULL);
		return (void *) csm_get(obj);
	} else
		return NULL;
}

static void csm_debug_dump_non_free()
{
	int i = 0;
	csm_mem_ctl_t *ptr;
	MDBG_LOCK;
	list_for_each_entry(ptr, &csm_dbg_mem.m, lh) {
		printf("\t%d: [%s:%d] ptr=%p, size=%zd, age=%d\n", (++i),
		       ptr->file, ptr->line, (ptr + 1), ptr->size,
		       ptr->age);
	}
	printf("Summary:\n");
	printf("\tmemory size:  (%zd/%zd)bytes (current/max)\n",
	       csm_dbg_mem.size, csm_dbg_mem.maxsize);
	printf("\tmemory blocks:(%d/%d) (current/max)\n", csm_dbg_mem.num,
	       csm_dbg_mem.maxnum);
	MDBG_UNLOCK;
}

static void csm_debug_dump_history()
{
	int i = 0;
	csm_mem_history_t *ptr;
	MDBG_LOCK;
	list_for_each_entry(ptr, &csm_dbg_mem.history, lh) {
		printf("\t%d: [%s:%d]  num=%d, maxnum=%d\n", (++i),
		       ptr->file, ptr->line, ptr->num, ptr->num_max);
	}
	MDBG_UNLOCK;
}

static void csm_debug_dump_increase()
{
	int i = 0;
	csm_mem_history_t *ptr;
	MDBG_LOCK;
	list_for_each_entry(ptr, &csm_dbg_mem.history, lh) {
		if (ptr->num_max>ptr->num_max_last) {
			printf("\t%d: [%s:%d]  num=%d, num_max=%d, last_num_max=%d, increased %d\n", (++i),
		       ptr->file, ptr->line, ptr->num, ptr->num_max, ptr->num_max_last, (ptr->num_max-ptr->num_max_last));
			ptr->num_max_last = ptr->num_max;
		}
	}
	MDBG_UNLOCK;
}


void csm_debug_memory_dump(int type)
{
	if (type==1) {
		csm_debug_dump_history();
	} else if (type==2) {
		csm_debug_dump_increase();
	} else {
		csm_debug_dump_non_free();
	}
}

#endif
