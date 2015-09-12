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

#include <config/defaults.h>

#include "config-voicestreams.h"
#include "config.h"

#include <libs/daemon/console.h>
#include <libs/comm/comm.h>

#include <string.h>
#include <stdlib.h>
#include <glib.h>

static char **config_voicestreams_streamnames = NULL;
static int config_voicestreams_streamnames_length = 0;

static int config_voicestreams_streamnames_load(void) {
	char **config_groups;
	int i, j;
	int length;
	int oldlength;
	int slen;
	char *tmp;

	length = 0;
	config_groups = config_get_groups(&oldlength);
	if (oldlength == 0)
		return 0;

	for (i = 0; i < oldlength; i++) {
		if (strstr(config_groups[i], "stream-") == NULL)
			continue;

		// Checking if repeater hosts variable is defined.
		tmp = config_voicestreams_get_repeaterhosts(config_groups[i]);
		if (tmp == NULL || strlen(tmp) == 0) {
			free(tmp);
			continue;
		}
		free(tmp);

		length++;
	}

	if (length == 0)
		return 0;

	config_voicestreams_streamnames = (char **)malloc(sizeof(char *) * (length+1));
	if (!config_voicestreams_streamnames)
		return 0;

	for (i = 0, j = 0; i < oldlength; i++) {
		if ((*config_groups) == NULL)
			break;

		if (strstr(config_groups[i], "stream-") == NULL)
			continue;

		// Checking if repeater hosts variable is defined.
		tmp = config_voicestreams_get_repeaterhosts(config_groups[i]);
		if (tmp == NULL || strlen(tmp) == 0) {
			free(tmp);
			continue;
		}
		free(tmp);

		slen = strlen(config_groups[i])+1;
		config_voicestreams_streamnames[j] = (char *)malloc(slen);
		if (config_voicestreams_streamnames[j] == NULL)
			break;

		strncpy(config_voicestreams_streamnames[j], config_groups[i], slen);
		j++;
	}

	config_voicestreams_streamnames[j] = NULL;

	return j; // Length
}

char **config_voicestreams_streamnames_get(void) {
	return config_voicestreams_streamnames;
}

char *config_voicestreams_get_streamname_for_repeater(struct in_addr *ip, int timeslot) {
	char *config_hosts;
	struct in_addr resolved_ip;
	int i;
	char *tok = NULL;

	for (i = 0; i < config_voicestreams_streamnames_length; i++) {
		if (config_voicestreams_streamnames[i] == NULL)
			break;

		if (config_voicestreams_get_timeslot(config_voicestreams_streamnames[i]) != timeslot)
			continue;

		config_hosts = config_voicestreams_get_repeaterhosts(config_voicestreams_streamnames[i]);
		if (config_hosts == NULL || strlen(config_hosts) == 0)
			continue;

		// Iterating through stream's defined repeater hosts.
		tok = strtok(config_hosts, ",");
		if (tok) {
			do {
				if (comm_hostname_to_ip(tok, &resolved_ip)) { // Hostname can be resolved to an IP and it matches?
					if (memcmp(&resolved_ip, ip, sizeof(struct in_addr)) == 0) {
						free(config_hosts);
						return config_voicestreams_streamnames[i];
					}
				} else {
					if (strcmp(tok, comm_get_ip_str(ip)) == 0) { // Hostname can't be resolved but it matches?
						free(config_hosts);
						return config_voicestreams_streamnames[i];
					}
				}

				tok = strtok(NULL, ",");
			} while (tok != NULL);
		}
		free(config_hosts);
	}
	return NULL;
}

int config_voicestreams_get_enabled(char *streamname) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 1;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, "enabled", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, "enabled", value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char *config_voicestreams_get_repeaterhosts(char *streamname) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	if (streamname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "";
	value = g_key_file_get_string(config_get_keyfile(), streamname, "repeaterhosts", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(config_get_keyfile(), streamname, "repeaterhosts", value);
		}
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char *config_voicestreams_get_savefiledir(char *streamname) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	if (streamname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "";
	value = g_key_file_get_string(config_get_keyfile(), streamname, "savefiledir", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(config_get_keyfile(), streamname, "savefiledir", value);
		}
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_savetorawfile(char *streamname) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, "savetorawfile", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, "savetorawfile", value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_timeslot(char *streamname) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 1;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, "timeslot", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, "timeslot", value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

void config_voicestreams_init(void) {
	int i;
	char *tmp;

	config_voicestreams_streamnames_length = config_voicestreams_streamnames_load();
	console_log("config: loaded %u voice stream configs\n", config_voicestreams_streamnames_length);
#ifndef DECODEVOICE
	if (config_voicestreams_streamnames_length > 0)
		console_log("config warning: voice streams defined in config but voice decoding is not compiled in\n");
#endif

	// We read everything, a default value will be set for non-existent keys in the config file.
	for (i = 0; i < config_voicestreams_streamnames_length; i++) {
		config_voicestreams_get_enabled(config_voicestreams_streamnames[i]);
		tmp = config_voicestreams_get_repeaterhosts(config_voicestreams_streamnames[i]);
		free(tmp);
		tmp = config_voicestreams_get_savefiledir(config_voicestreams_streamnames[i]);
		free(tmp);
		config_voicestreams_get_savetorawfile(config_voicestreams_streamnames[i]);
		config_voicestreams_get_timeslot(config_voicestreams_streamnames[i]);
	}

	config_writeconfigfile();
}

void config_voicestreams_deinit(void) {
	console_log("config: voicestreams deinit\n");
	g_strfreev(config_voicestreams_streamnames);
}
