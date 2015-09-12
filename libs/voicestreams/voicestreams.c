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

#include "voicestreams.h"

#include <libs/config/config-voicestreams.h>
#include <libs/daemon/console.h>
#include <libs/comm/comm.h>

#include <string.h>
#include <stdlib.h>

static voicestream_t *voicestreams = NULL;

voicestream_t *voicestreams_get(void) {
	return voicestreams;
}

voicestream_t *voicestreams_get_stream_for_repeater(struct in_addr *ip, int timeslot) {
	char *config_hosts;
	struct in_addr resolved_ip;
	char *tok = NULL;
	voicestream_t *vs = voicestreams;

	while (vs != NULL) {
		if (config_voicestreams_get_timeslot(vs->name) != timeslot) {
			vs = vs->next;
			continue;
		}

		config_hosts = config_voicestreams_get_repeaterhosts(vs->name);
		if (config_hosts == NULL || strlen(config_hosts) == 0) {
			vs = vs->next;
			continue;
		}

		// Iterating through stream's defined repeater hosts.
		tok = strtok(config_hosts, ",");
		if (tok) {
			do {
				if (comm_hostname_to_ip(tok, &resolved_ip)) { // Hostname can be resolved to an IP and it matches?
					if (memcmp(&resolved_ip, ip, sizeof(struct in_addr)) == 0) {
						free(config_hosts);
						return vs;
					}
				} else {
					if (strcmp(tok, comm_get_ip_str(ip)) == 0) { // Hostname can't be resolved but it matches?
						free(config_hosts);
						return vs;
					}
				}

				tok = strtok(NULL, ",");
			} while (tok != NULL);
		}
		free(config_hosts);

		vs = vs->next;
	}

	return NULL;
}

void voicestreams_list(void) {
	char *hosts;
	char *dir;
	voicestream_t *vs;

	if (voicestreams == NULL) {
		console_log("no voice streams loaded.\n");
		return;
	}
	console_log("voice streams:\n");

	vs = voicestreams;
	while (vs != NULL) {
		hosts = config_voicestreams_get_repeaterhosts(vs->name);
		dir = config_voicestreams_get_savefiledir(vs->name);

		console_log("%s: enabled: %u rptrhosts: %s ts: %u savedir: %s saveraw: %u\n", vs->name,
			config_voicestreams_get_enabled(vs->name),
			hosts,
			config_voicestreams_get_timeslot(vs->name),
			(strlen(dir) == 0 ? "." : dir),
			config_voicestreams_get_savetorawfile(vs->name));

		free(hosts);
		free(dir);

		vs = vs->next;
	}
}

void voicestreams_init(void) {
	char **streamnames = config_voicestreams_get_streamnames();
	char **streamnames_i = streamnames;
	voicestream_t *new_vs;

	console_log("voicestreams init:\n");
	if (streamnames == NULL) {
		console_log("no voice streams defined in config file.\n");
		return;
	}

	while (*streamnames_i != NULL) {
		console_log("  %s: ", *streamnames_i);
		new_vs = (voicestream_t *)malloc(sizeof(voicestream_t));
		if (!new_vs) {
			console_log("warning: couldn't allocate memory\n");
			continue;
		}
		new_vs->name = strdup(*streamnames_i);
		if (!new_vs->name) {
			console_log("warning: couldn't allocate memory\n");
			free(new_vs);
			continue;
		}
		new_vs->next = voicestreams;
		voicestreams = new_vs;

		console_log("initialized\n");

		streamnames_i++;
	}
	config_voicestreams_free_streamnames(streamnames);
}

void voicestreams_deinit(void) {
	voicestream_t *vs;

	while (voicestreams != NULL) {
		vs = voicestreams->next;
		free(voicestreams);
		voicestreams = vs;
	}
}
