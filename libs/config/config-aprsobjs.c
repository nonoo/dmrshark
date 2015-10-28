/*
 * This file is part of dmrshark.
 *
 * dmrshark is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dmrshark is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dmrshark.  If not, see <http://www.gnu.org/licenses/>.
**/

#include DEFAULTCONFIG

#include "config-aprsobjs.h"
#include "config.h"

#include <libs/daemon/console.h>

#include <string.h>
#include <stdlib.h>
#include <glib.h>

char **config_aprsobjs_get_objnames(void) {
	char **config_groups;
	char **result;
	int i, j;
	int length;
	int oldlength;

	length = 0;
	config_groups = config_get_groups(&oldlength);
	if (oldlength == 0)
		return 0;

	for (i = 0; i < oldlength; i++) {
		if (strstr(config_groups[i], "aprsobj-") == NULL)
			continue;

		// Checking if enabled variable is defined.
		if (!config_aprsobjs_get_enabled(config_groups[i]))
			continue;

		length++;
	}

	if (length == 0) {
		config_free_groups(config_groups);
		return 0;
	}

	result = (char **)malloc(sizeof(char *) * (length+1));
	if (!result) {
		config_free_groups(config_groups);
		return 0;
	}

	for (i = 0, j = 0; i < oldlength; i++) {
		if ((*config_groups) == NULL)
			break;

		if (strstr(config_groups[i], "aprsobj-") == NULL)
			continue;

		// Checking if enabled variable is defined.
		if (!config_aprsobjs_get_enabled(config_groups[i]))
			continue;

		result[j] = strdup(config_groups[i]);
		if (result[j] == NULL)
			break;

		j++;
	}

	result[j] = NULL;
	config_free_groups(config_groups);

	return result;
}

void config_aprsobjs_free_objnames(char **objnames) {
	g_strfreev(objnames);
}

int config_aprsobjs_get_enabled(char *objname) {
	GError *error = NULL;
	int value = 0;
	char *key = "enabled";
	int defaultvalue = 1;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), objname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), objname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

double config_aprsobjs_get_latitude(char *objname) {
	GError *error = NULL;
	double value = 0;
	char *key = "latitude";
	double defaultvalue;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = 0;
	value = g_key_file_get_double(config_get_keyfile(), objname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), objname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char config_aprsobjs_get_latitude_ch(char *objname) {
	GError *error = NULL;
	char *value = NULL;
	char result = 0;
	char *key = "latitude-ch";
	char *defaultvalue = NULL;

	if (objname == NULL)
		return 0;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "N";
	value = g_key_file_get_string(config_get_keyfile(), objname, key, &error);
	if (error || value == NULL) {
		result = defaultvalue[0];
		g_key_file_set_string(config_get_keyfile(), objname, key, defaultvalue);
	} else  {
		result = value[0];
		free(value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return result;
}

double config_aprsobjs_get_longitude(char *objname) {
	GError *error = NULL;
	double value = 0;
	char *key = "longitude";
	double defaultvalue;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = 0;
	value = g_key_file_get_double(config_get_keyfile(), objname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), objname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char config_aprsobjs_get_longitude_ch(char *objname) {
	GError *error = NULL;
	char *value = NULL;
	char result = 0;
	char *key = "longitude-ch";
	char *defaultvalue = NULL;

	if (objname == NULL)
		return 0;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "E";
	value = g_key_file_get_string(config_get_keyfile(), objname, key, &error);
	if (error || value == NULL) {
		result = defaultvalue[0];
		g_key_file_set_string(config_get_keyfile(), objname, key, defaultvalue);
	} else  {
		result = value[0];
		free(value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return result;
}

char *config_aprsobjs_get_description(char *objname) {
	GError *error = NULL;
	char *value = NULL;
	char *key = "description";
	char *defaultvalue = NULL;

	if (objname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "";
	value = g_key_file_get_string(config_get_keyfile(), objname, key, &error);
	if (error || value == NULL) {
		value = strdup(defaultvalue);
		if (value)
			g_key_file_set_string(config_get_keyfile(), objname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char config_aprsobjs_get_table_ch(char *objname) {
	GError *error = NULL;
	char *value = NULL;
	char result = 0;
	char *key = "table-ch";
	char *defaultvalue = NULL;

	if (objname == NULL)
		return 0;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "/";
	value = g_key_file_get_string(config_get_keyfile(), objname, key, &error);
	if (error || value == NULL) {
		result = defaultvalue[0];
		g_key_file_set_string(config_get_keyfile(), objname, key, defaultvalue);
	} else  {
		result = value[0];
		free(value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return result;
}

char config_aprsobjs_get_symbol_ch(char *objname) {
	GError *error = NULL;
	char *value = NULL;
	char result = 0;
	char *key = "symbol-ch";
	char *defaultvalue = NULL;

	if (objname == NULL)
		return 0;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "r";
	value = g_key_file_get_string(config_get_keyfile(), objname, key, &error);
	if (error || value == NULL) {
		result = defaultvalue[0];
		g_key_file_set_string(config_get_keyfile(), objname, key, defaultvalue);
	} else  {
		result = value[0];
		free(value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return result;
}

void config_aprsobjs_init(void) {
	int i;
	char *tmp;
	char **aprsobjs;
	char **aprsobjs_i;

	aprsobjs = config_aprsobjs_get_objnames();
	aprsobjs_i = aprsobjs;
	i = 0;
	if (aprsobjs) {
		// We read everything, a default value will be set for non-existent keys in the config file.
		while (*aprsobjs_i != NULL) {
			config_aprsobjs_get_enabled(aprsobjs[i]);
			config_aprsobjs_get_latitude(aprsobjs[i]);
			config_aprsobjs_get_latitude_ch(aprsobjs[i]);
			config_aprsobjs_get_longitude(aprsobjs[i]);
			config_aprsobjs_get_longitude_ch(aprsobjs[i]);
			tmp = config_aprsobjs_get_description(aprsobjs[i]);
			free(tmp);
			config_aprsobjs_get_table_ch(aprsobjs[i]);
			config_aprsobjs_get_symbol_ch(aprsobjs[i]);

			i++;
			aprsobjs_i++;
		}
		config_aprsobjs_free_objnames(aprsobjs);
	}

	console_log("config: loaded %u aprs object configs\n", i);
	config_writeconfigfile();
}
