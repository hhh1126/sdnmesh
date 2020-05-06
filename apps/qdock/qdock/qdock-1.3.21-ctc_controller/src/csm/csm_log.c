/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.                  **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#include "csm_utils.h"
enum {
	LOG_OUTPUT_NONE = 0,
	LOG_OUTPUT_STDOUT = 1,
	LOG_OUTPUT_SYSLOG = 2
};

#define LOG_INDEX_INVALID	(-1)
#define LOG_MAXNUMS 8
typedef struct {
	const char *name;
	int level;
	int valid;
} log_entry_t;

static const char *g_log_level_names[] = {
	"off",
	"error",
	"warn",
	"notice",
	"info",
	"debug",
};


#ifdef COLORFUL_WORLD
static const char *g_log_level_fmts[] = {
	COLORFUL_STR(COLOR_BLUE, "Off..."),
	COLORFUL_STR(COLOR_RED, "Error."),
	COLORFUL_STR(COLOR_YELLOW, "Warn.."),
	COLORFUL_STR(COLOR_CYAN, "Notice"),
	COLORFUL_STR(COLOR_GREEN, "Info.."),
	COLORFUL_STR(COLOR_PURPLE, "Debug."),
};
#else
static const char *g_log_level_fmts[] = {
	"Off...",
	"Error.",
	"Warn..",
	"Notice",
	"Info..",
	"Debug.",
};
#endif

typedef struct {
	const char *name;
	int value;
} name_val_t;

static name_val_t g_log_outputs[] = {
	{"none", LOG_OUTPUT_NONE},
	{"stdout", LOG_OUTPUT_STDOUT},
	{"syslog", LOG_OUTPUT_SYSLOG}
};

static log_entry_t g_log_entries[LOG_MAXNUMS];
static int g_log_output;
static pthread_mutex_t g_log_mutex;

static const char *csm_level_name(int level)
{
	int ind;
	if (level < LOG_CRIT)
		level = LOG_CRIT;

	else if (level > LOG_DEBUG)
		level = LOG_DEBUG;
	ind = level - LOG_CRIT;
	return g_log_level_names[ind];
}

int csm_level_no(const char *level_name)
{
	int ind;
	for (ind = 0;
	     ind <
	     sizeof(g_log_level_names) / sizeof(g_log_level_names[0]);
	     ind++) {
		if (strcasecmp(g_log_level_names[ind], level_name) == 0) {
			return ind + LOG_CRIT;
		}
	}
	return -1;
}

static const char *csm_output_name(int output)
{
	if (output < LOG_OUTPUT_NONE || output > LOG_OUTPUT_SYSLOG)
		output = LOG_OUTPUT_NONE;
	return g_log_outputs[output].name;
}

void csm_log_init(void)
{
	int i = 0;
	for (i = 0; i < LOG_MAXNUMS; i++) {
		g_log_entries[i].valid = LOG_INDEX_INVALID;
		g_log_entries[i].name = NULL;
		g_log_entries[i].level = 0;
	}
	pthread_mutex_init(&g_log_mutex, NULL);
	g_log_output = LOG_OUTPUT_STDOUT;
}

int csm_log_register(const char *name, int default_level)
{
	int i, handle = LOG_INDEX_INVALID;
	for (i = 0; i < LOG_MAXNUMS; i++) {
		if (g_log_entries[i].valid < 0) {
			handle = i;
			g_log_entries[i].valid = i;
			g_log_entries[i].name = name;
			g_log_entries[i].level = default_level;
			break;
		}
	}
	return handle;
}

void csm_log_printf(int handle, int level, const char *func,
		    uint32_t line, const char *fmt, ...)
{
	va_list ap;
	int index;
	if (handle < 0 || handle >= LOG_MAXNUMS)
		return;
	if (LOG_OUTPUT_NONE == g_log_output)
		return;
	if (level > g_log_entries[handle].level)
		return;
	va_start(ap, fmt);
	index = level - LOG_CRIT;
	pthread_mutex_lock(&g_log_mutex);
	if (LOG_OUTPUT_STDOUT == g_log_output) {
		if (index >= 0
		    && index <
		    sizeof(g_log_level_names) /
		    sizeof(g_log_level_names[0]))
			printf("%010lu [%s] [%s] (%-20.20s:%04u) ",
			       time(NULL), g_log_level_fmts[index],
			       g_log_entries[handle].name, func, line);
		vprintf(fmt, ap);
	} else {
		char format[256];
		snprintf(format, 256, "%010lu [%s] (%-20.20s:%04u) %s",
			time(NULL), g_log_entries[handle].name, func, line, fmt);
		vsyslog(level, format, ap);
	}
	pthread_mutex_unlock(&g_log_mutex);
	va_end(ap);
}

void csm_log_dump(int handle, char *title, const char *func,
		  uint32_t line, uint8_t *buf, int len)
{
	int i, index = LOG_DEBUG - LOG_CRIT;
	char *strbuf, *pos;
	if (handle < 0 || handle >= LOG_MAXNUMS)
		return;
	if (LOG_OUTPUT_NONE == g_log_output)
		return;
	if (LOG_DEBUG > g_log_entries[handle].level)
		return;

	strbuf = CSM_MALLOC(128				/* header */
			+ len * 3			/* data */
			+ ((len - 1) / 8) * 4		/* 4 blanks */
			+ ((len - 1) / 16) + 1		/* line break */
			+ 1 + 1);			/* last line break + ending */
	if(NULL == strbuf)
		return;

	pos = strbuf;

	if (LOG_OUTPUT_STDOUT == g_log_output)
		pos += snprintf(pos, 120, "%010lu [%s] [%-6s] (%-20.20s:%04u) %s",
				time(NULL), g_log_level_fmts[index],
				g_log_entries[handle].name, func, line, title);
	else
		pos += snprintf(pos, 120, "%010lu [%-6s] (%-20.20s:%04u) %s",
				time(NULL), g_log_entries[handle].name, func, line, title);

	for (i = 0; i < len; i++) {
		if ((i & 0xf) == 0)
			pos += sprintf(pos, "\n");
		else if ((i & 0x7) == 0)
			pos += sprintf(pos, "    ");
		pos += sprintf(pos, "%02x ", buf[i]);
	}
	pos += sprintf(pos, "\n");
	*pos = '\0';

	pthread_mutex_lock(&g_log_mutex);
	if (LOG_OUTPUT_STDOUT == g_log_output) {
		printf("%s", strbuf);
	} else {
		syslog(LOG_DEBUG, "%s", strbuf);
	}
	pthread_mutex_unlock(&g_log_mutex);

	CSM_FREE(strbuf);
}

#if 1
int csm_log_settings_show(char *rep, int rep_len)
{
	int i = 0;
	char *pos, *end;
	pos = rep;
	end = pos + rep_len;
	pos +=
	    snprintf(pos, end - pos,
		     "log output to %s, all module log settings:\n",
		     csm_output_name(g_log_output));
	if (pos >= end)
		return pos - rep;
	for (i = 0; i < LOG_MAXNUMS; i++) {
		if (g_log_entries[i].valid >= 0) {
			pos +=
			    snprintf(pos, end - pos,
				     "\t%-6s: handler %u; level %s\n",
				     g_log_entries[i].name, i,
				     csm_level_name(g_log_entries
						    [i].level));
			if (pos >= end)
				break;
		}
	}
	return pos - rep;
}


#else
void csm_log_settings_show(void)
{
	int i = 0;
	printf("log output to [%s]\n", csm_output_name(g_log_output));
	printf("levels:\n");
	for (i = 0;
	     i < sizeof(g_log_level_names) / sizeof(g_log_level_names[0]);
	     i++) {
		printf("\t%u: %3s\n", i, g_log_level_names[i]);
	}
	printf("modules:\n");
	for (i = 0; i < LOG_MAXNUMS; i++) {
		if (g_log_entries[i].valid >= 0) {
			printf("\t%-6s: handler %u; level %s\n",
			       g_log_entries[i].name, i,
			       csm_level_name(g_log_entries[i].level));
		}
	}
	printf("\n");
}


#endif
int csm_log_set_level(char *name, const char *level_name)
{
	int i = 0, level;
	if (NULL == name || NULL == level_name)
		return -1;
	for (i = 0; i < LOG_MAXNUMS; i++) {
		if (g_log_entries[i].valid >= 0
		    && strcasestr(g_log_entries[i].name, name)) {
			level = csm_level_no(level_name);
			if (level < 0)
				return -1;
			g_log_entries[i].level = level;
			return 0;
		}
	}
	return -1;
}

int csm_log_set_level_by_handle(int handle, const char *level_name)
{
	int level;
	if (handle < 0 || handle >= LOG_MAXNUMS || NULL == level_name)
		return -1;
	level = csm_level_no(level_name);
	if (level < 0)
		return -1;
	g_log_entries[handle].level = level;
	return 0;
}

int csm_log_set_output(const char *output_name)
{
	int i = 0, old_output = g_log_output;

	if (NULL == output_name)
		return -1;
	for (i = 0;
	     i < sizeof(g_log_outputs) / sizeof(g_log_outputs[0]); i++) {
		if (0 == strcasecmp(output_name, g_log_outputs[i].name)) {
			g_log_output = g_log_outputs[i].value;

			if(old_output == LOG_OUTPUT_SYSLOG
				&& g_log_output != LOG_OUTPUT_SYSLOG) {
				closelog();
			} else if(old_output != LOG_OUTPUT_SYSLOG
				&& g_log_output == LOG_OUTPUT_SYSLOG) {
				openlog("soniq", LOG_NDELAY | LOG_NOWAIT | LOG_PID, LOG_USER);
			}
			return 0;
		}
	}
	return -1;
}
