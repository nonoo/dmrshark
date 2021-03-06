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

#include "config-voicestreams.h"
#include "config.h"

#include <libs/daemon/console.h>

#include <string.h>
#include <stdlib.h>
#include <glib.h>

char **config_voicestreams_get_streamnames(void) {
	char **config_groups;
	char **result;
	int i, j;
	int length;
	int oldlength;
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

		if (strstr(config_groups[i], "stream-") == NULL)
			continue;

		// Checking if repeater hosts variable is defined.
		tmp = config_voicestreams_get_repeaterhosts(config_groups[i]);
		if (tmp == NULL || strlen(tmp) == 0) {
			free(tmp);
			continue;
		}
		free(tmp);

		result[j] = strdup(config_groups[i]);
		if (result[j] == NULL)
			break;

		j++;
	}

	result[j] = NULL;
	config_free_groups(config_groups);

	return result;
}

void config_voicestreams_free_streamnames(char **streamnames) {
	g_strfreev(streamnames);
}

int config_voicestreams_get_enabled(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "enabled";
	int defaultvalue = 1;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char *config_voicestreams_get_repeaterhosts(char *streamname) {
	GError *error = NULL;
	char *value = NULL;
	char *key = "repeaterhosts";
	char *defaultvalue = NULL;

	if (streamname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "";
	value = g_key_file_get_string(config_get_keyfile(), streamname, key, &error);
	if (error || value == NULL) {
		value = strdup(defaultvalue);
		if (value)
			g_key_file_set_string(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char *config_voicestreams_get_savefiledir(char *streamname) {
	GError *error = NULL;
	char *value = NULL;
	char *key = "savefiledir";
	char *defaultvalue = NULL;

	if (streamname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "";
	value = g_key_file_get_string(config_get_keyfile(), streamname, key, &error);
	if (error || value == NULL) {
		value = strdup(defaultvalue);
		if (value)
			g_key_file_set_string(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_savetorawambefile(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "savetorawambefile";
	int defaultvalue;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = 0;
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_savedecodedtorawfile(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "savedecodedtorawfile";
	int defaultvalue;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = 0;
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_savedecodedtomp3file(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "savedecodedtomp3file";
	int defaultvalue;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = 0;
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_minmp3bitrate(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "minmp3bitrate";
	int defaultvalue = 32;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_mp3bitrate(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "mp3bitrate";
	int defaultvalue = 64;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_mp3quality(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "mp3quality";
	int defaultvalue;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = 0;
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_mp3vbr(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "mp3vbr";
	int defaultvalue = 0;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_timeslot(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "timeslot";
	int defaultvalue = 1;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

int config_voicestreams_get_decodequality(char *streamname) {
	GError *error = NULL;
	int value = 0;
	char *key = "decodequality";
	int defaultvalue = 3;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_integer(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char *config_voicestreams_get_playrawfileatcallstart(char *streamname) {
	GError *error = NULL;
	char *value = NULL;
	char *key = "playrawfileatcallstart";
	char *defaultvalue = NULL;

	if (streamname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "call-start.raw";
	value = g_key_file_get_string(config_get_keyfile(), streamname, key, &error);
	if (error || value == NULL) {
		value = strdup(defaultvalue);
		if (value)
			g_key_file_set_string(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

double config_voicestreams_get_rawfileatcallstartgain(char *streamname) {
	GError *error = NULL;
	double value = 0;
	char *key = "rawfileatcallstartgain";
	double defaultvalue = 0.6;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_double(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_double(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

char *config_voicestreams_get_playrawfileatcallend(char *streamname) {
	GError *error = NULL;
	char *value = NULL;
	char *key = "playrawfileatcallend";
	char *defaultvalue = NULL;

	if (streamname == NULL)
		return NULL;

	pthread_mutex_lock(config_get_mutex());
	defaultvalue = "call-end.raw";
	value = g_key_file_get_string(config_get_keyfile(), streamname, key, &error);
	if (error || value == NULL) {
		value = strdup(defaultvalue);
		if (value)
			g_key_file_set_string(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

double config_voicestreams_get_rawfileatcallendgain(char *streamname) {
	GError *error = NULL;
	double value = 0;
	char *key = "rawfileatcallendgain";
	double defaultvalue = 0.6;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_double(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_double(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

double config_voicestreams_get_rmsminsamplevalue(char *streamname) {
	GError *error = NULL;
	double value = 0;
	char *key = "rmsminsamplevalue";
	double defaultvalue = 0.015;

	pthread_mutex_lock(config_get_mutex());
	value = g_key_file_get_double(config_get_keyfile(), streamname, key, &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_double(config_get_keyfile(), streamname, key, value);
	}
	pthread_mutex_unlock(config_get_mutex());
	return value;
}

void config_voicestreams_init(void) {
	int i;
	char *tmp;
	char **voicestreams;
	char **voicestreams_i;

	voicestreams = config_voicestreams_get_streamnames();
	voicestreams_i = voicestreams;
	i = 0;
	if (voicestreams) {
		// We read everything, a default value will be set for non-existent keys in the config file.
		while (*voicestreams_i != NULL) {
			config_voicestreams_get_enabled(voicestreams[i]);
			tmp = config_voicestreams_get_repeaterhosts(voicestreams[i]);
			free(tmp);
			tmp = config_voicestreams_get_savefiledir(voicestreams[i]);
			free(tmp);
			config_voicestreams_get_savetorawambefile(voicestreams[i]);
			config_voicestreams_get_savedecodedtorawfile(voicestreams[i]);
			config_voicestreams_get_savedecodedtomp3file(voicestreams[i]);
#ifndef MP3ENCODEVOICE
			if (config_voicestreams_get_savedecodedtomp3file(voicestreams[i]))
				console_log("config warning: voice stream %s has mp3 encoding enabled, but mp3 encoding is not compiled in\n", voicestreams[i]);
#endif
			config_voicestreams_get_minmp3bitrate(voicestreams[i]);
			config_voicestreams_get_mp3bitrate(voicestreams[i]);
			config_voicestreams_get_mp3quality(voicestreams[i]);
			config_voicestreams_get_mp3vbr(voicestreams[i]);
			config_voicestreams_get_timeslot(voicestreams[i]);
			config_voicestreams_get_decodequality(voicestreams[i]);
			tmp = config_voicestreams_get_playrawfileatcallstart(voicestreams[i]);
			free(tmp);
			config_voicestreams_get_rawfileatcallstartgain(voicestreams[i]);
			tmp = config_voicestreams_get_playrawfileatcallend(voicestreams[i]);
			free(tmp);
			config_voicestreams_get_rawfileatcallendgain(voicestreams[i]);
			config_voicestreams_get_rmsminsamplevalue(voicestreams[i]);

			i++;
			voicestreams_i++;
		}
		config_voicestreams_free_streamnames(voicestreams);
	}

	console_log("config: loaded %u voice stream configs\n", i);
#ifndef AMBEDECODEVOICE
	if (i > 0)
		console_log("config warning: voice streams defined in config but voice decoding is not compiled in\n");
#endif

	config_writeconfigfile();
}
