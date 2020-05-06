/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/

#include "csm.h"

#define PPREFIX "[CSMgr]: "


void *csm_load_plugins(DIR * dir, char *dirname, uint32_t version,
		       uint32_t magic)
{
	struct csm_plugin *head = NULL;
	char *pname;

	if (dir == NULL)
		goto bail;

	while ((pname = csm_get_next_plugin_name(dir))) {
		char *path;
		if (asprintf(&path, "%s/%s", dirname, pname) > 0) {
			void *handle = dlopen(path, RTLD_NOW);	//LAZY);
			CSM_DEBUG(PPREFIX "Searching in file:%s.\n",
				  pname);
			if (handle) {
				struct csm_plugin_file_desc *desc = NULL;
				csm_plugin_file_entry_func get_func;
				get_func =
				    dlsym(handle,
					  CSM_PLUGIN_FILE_ENTRY_NAME);
				if (get_func
					    && (NULL != (desc = (*get_func)()))
					    && (desc->version == version)
					    && (desc->magic == magic)) {
					int i;
					for (i = 0;
					     i < desc->plugin_num;
					     i++) {
						struct csm_plugin *plugin =
						    CSM_MALLOC(sizeof
							       (struct
								csm_plugin));
						if (!plugin)
							continue;

						plugin->file_name =
						    strdup(pname);
						plugin->plugin_name
						    =
						    strdup
						    (desc->plugin
						     [i]->name);
						plugin->plugin =
						    desc->plugin
							    [i];
						CSM_DEBUG(PPREFIX
							  "\tplugin:%s found ...\n",
							  plugin->plugin_name);

						INSERT_LIST(head,
							    plugin);
					}
				} else {
					CSM_WARNING(PPREFIX "Found non plugin in file:%s.\n",
						  pname);
					dlclose(handle);
				}
			} else {
				CSM_WARNING(PPREFIX "load plugin %s failed: %s\n", pname, dlerror());
			}
			free(path);
			/* coverity[leaked_storage] - The dynamic plugin lib will be used throughout the life of the program
			 * These libs will be unloaded When the program terminates */
		}
	}

      bail:
	return head;
}

csm_plugin_head *csm_find_plugin(void *plugins, const char *name)
{
	struct csm_plugin *plugin = (struct csm_plugin *) plugins;

	while (plugin) {
		if (strcmp(name, plugin->plugin_name) == 0)
			break;
		plugin = plugin->next;
	}

	if (plugin)
		return plugin->plugin;
	else
		return NULL;
}
