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
#include "voicestreams-process.h"
#include "voicestreams-mp3.h"

#include <libs/config/config-voicestreams.h>
#include <libs/daemon/console.h>
#include <libs/comm/comm.h>

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

static voicestream_t *voicestreams = NULL;

char *voicestreams_get_stream_filename(voicestream_t *voicestream, char *extension) {
	static char fn[255];
	char *dir;
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);

	dir = voicestream->savefiledir;
	if (dir == NULL || strlen(dir) == 0)
		dir = ".";
	snprintf(fn, sizeof(fn), "%s/dmrshark-%s-%.4u%.2u%.2u%s", dir, voicestream->name, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, extension);

	return fn;
}

voicestream_t *voicestreams_get_stream_for_repeater(struct in_addr *ip, int timeslot) {
	struct in_addr resolved_ip;
	char *tok = NULL;
	voicestream_t *vs = voicestreams;
	voicestream_t *wildcard_host_vs = NULL;

	while (vs != NULL) {
		if (vs->timeslot != timeslot || !vs->enabled) {
			vs = vs->next;
			continue;
		}

		if (vs->repeaterhosts == NULL || strlen(vs->repeaterhosts) == 0) {
			vs = vs->next;
			continue;
		}

		// Iterating through stream's defined repeater hosts.
		tok = strtok(vs->repeaterhosts, ",");
		if (tok) {
			do {
				if (strcmp(tok, "*") == 0) // Found a wildcard host, storing it.
					wildcard_host_vs = vs;

				if (comm_hostname_to_ip(tok, &resolved_ip)) { // Hostname can be resolved to an IP and it matches?
					if (memcmp(&resolved_ip, ip, sizeof(struct in_addr)) == 0)
						return vs;
				} else {
					if (strcmp(tok, comm_get_ip_str(ip)) == 0) // Hostname can't be resolved but it matches?
						return vs;
				}

				tok = strtok(NULL, ",");
			} while (tok != NULL);
		}

		vs = vs->next;
	}

	return wildcard_host_vs;
}

voicestream_t *voicestreams_get_stream_by_name(char *name) {
	voicestream_t *vs = voicestreams;

	while (vs != NULL) {
		if (strcmp(vs->name, name) == 0)
			return vs;

		vs = vs->next;
	}
	return NULL;
}

void voicestreams_printlist(void) {
	voicestream_t *vs;

	if (voicestreams == NULL) {
		console_log("no voice streams loaded.\n");
		return;
	}
	console_log("voice streams:\n");

	vs = voicestreams;
	while (vs != NULL) {
		console_log("%s: enabled: %u rptrhosts: %s ts: %u quality: %u savedir: %s saveraw: %u savedecodedraw: %u savedecodedmp3: %u\n", vs->name,
			vs->enabled,
			vs->repeaterhosts,
			vs->timeslot,
			vs->decodequality,
			(strlen(vs->savefiledir) == 0 ? "." : vs->savefiledir),
			vs->savetorawfile,
			vs->savedecodedtorawfile,
			vs->savedecodedtomp3file);
		console_log("   minmp3br: %u mp3br: %u mp3quality: %u mp3vbr: %u rmsminsampval: %f\n",
			vs->minmp3bitrate,
			vs->mp3bitrate,
			vs->mp3quality,
			vs->mp3vbr,
			vs->rmsminsamplevalue);
		console_log("   callstartfile: %s (%f) callendfile: %s (%f)\n",
			vs->playrawfileatcallstart,
			vs->rawfileatcallstartgain,
			vs->playrawfileatcallend,
			vs->rawfileatcallendgain);

		vs = vs->next;
	}
}

void voicestreams_init(void) {
	char **streamnames = config_voicestreams_get_streamnames();
	char **streamnames_i = streamnames;
	voicestream_t *new_vs;
#ifdef AMBEDECODEVOICE
	char mbeversion[25];
#endif

	console_log("voicestreams init:\n");
	if (streamnames == NULL) {
		console_log("no voice streams defined in config file.\n");
		return;
	}

	while (*streamnames_i != NULL) {
		console_log("  initializing %s...\n", *streamnames_i);
		new_vs = (voicestream_t *)calloc(sizeof(voicestream_t), 1);
		if (!new_vs) {
			console_log("    warning: couldn't allocate memory\n");
			continue;
		}

		new_vs->name = strdup(*streamnames_i);
		if (!new_vs->name) {
			console_log("    warning: couldn't allocate memory\n");
			free(new_vs);
			continue;
		}
		new_vs->enabled = config_voicestreams_get_enabled(new_vs->name);
		new_vs->repeaterhosts = config_voicestreams_get_repeaterhosts(new_vs->name);
		new_vs->savefiledir = config_voicestreams_get_savefiledir(new_vs->name);
		new_vs->savetorawfile = config_voicestreams_get_savetorawfile(new_vs->name);
		new_vs->savedecodedtorawfile = config_voicestreams_get_savedecodedtorawfile(new_vs->name);
		new_vs->savedecodedtomp3file = config_voicestreams_get_savedecodedtomp3file(new_vs->name);
		new_vs->minmp3bitrate = config_voicestreams_get_minmp3bitrate(new_vs->name);
		new_vs->mp3bitrate = config_voicestreams_get_mp3bitrate(new_vs->name);
		new_vs->mp3quality = config_voicestreams_get_mp3quality(new_vs->name);
		new_vs->mp3vbr = config_voicestreams_get_mp3vbr(new_vs->name);
		new_vs->timeslot = config_voicestreams_get_timeslot(new_vs->name);
		new_vs->decodequality = config_voicestreams_get_decodequality(new_vs->name);
		new_vs->playrawfileatcallstart = config_voicestreams_get_playrawfileatcallstart(new_vs->name);
		new_vs->rawfileatcallstartgain = config_voicestreams_get_rawfileatcallstartgain(new_vs->name);
		new_vs->playrawfileatcallend = config_voicestreams_get_playrawfileatcallend(new_vs->name);
		new_vs->rawfileatcallendgain = config_voicestreams_get_rawfileatcallendgain(new_vs->name);
		new_vs->rmsminsamplevalue = config_voicestreams_get_rmsminsamplevalue(new_vs->name);

		new_vs->rms_vol = new_vs->avg_rms_vol = VOICESTREAMS_INVALID_RMS_VALUE;

#if defined(AMBEDECODEVOICE) && defined(MP3ENCODEVOICE)
		voicestreams_mp3_init(new_vs);
#endif

		new_vs->next = voicestreams;
		voicestreams = new_vs;

		streamnames_i++;
	}
	config_voicestreams_free_streamnames(streamnames);

#ifdef AMBEDECODEVOICE
	mbe_printVersion(mbeversion);
	console_log("voicestreams: using mbelib v%s for voice decoding\n", mbeversion);
#endif
}

void voicestreams_deinit(void) {
	voicestream_t *next_vs;

	console_log("voicestreams: deinit\n");

	while (voicestreams != NULL) {
#ifdef MP3ENCODEVOICE
		voicestreams_mp3_deinit(voicestreams);
#endif

		free(voicestreams->name);
		free(voicestreams->repeaterhosts);
		free(voicestreams->savefiledir);
		free(voicestreams->playrawfileatcallstart);
		free(voicestreams->playrawfileatcallend);

		next_vs = voicestreams->next;
		free(voicestreams);
		voicestreams = next_vs;
	}
}
