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

#include "repeaters.h"
#include "comm.h"
#include "snmp.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>
#include <libs/remotedb/remotedb.h>
#include <libs/base/dmr-handle.h>

#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

static repeater_t *repeaters = NULL;

static char *repeaters_get_readable_slot_state(repeater_slot_state_t state) {
	switch (state) {
		case REPEATER_SLOT_STATE_IDLE: return "idle";
		case REPEATER_SLOT_STATE_CALL_RUNNING: return "call running";
		case REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING: return "data receive running";
		default: return "unknown";
	}
}

char *repeaters_get_display_string_for_ip(struct in_addr *ipaddr) {
	repeater_t *foundrep;

	foundrep = repeaters_findbyip(ipaddr);
	if (foundrep && foundrep->callsign_lowercase[0] != 0)
		return foundrep->callsign_lowercase;
	if (comm_is_our_ipaddr(ipaddr))
		return "ds";

	return comm_get_ip_str(ipaddr);
}

char *repeaters_get_display_string(repeater_t *repeater) {
	if (repeater->callsign[0] == 0)
		return comm_get_ip_str(&repeater->ipaddr);
	else
		return repeater->callsign_lowercase;
}

repeater_t *repeaters_findbyip(struct in_addr *ipaddr) {
	repeater_t *repeater = repeaters;

	if (ipaddr == NULL)
		return NULL;

	while (repeater) {
		if (memcmp(&repeater->ipaddr, ipaddr, sizeof(struct in_addr)) == 0)
			return repeater;

		repeater = repeater->next;
	}
	return NULL;
}

repeater_t *repeaters_get_active(dmr_id_t src_id, dmr_id_t dst_id, dmr_call_type_t call_type) {
	repeater_t *repeater = repeaters;

	while (repeater) {
		if ((repeater->slot[0].state != REPEATER_SLOT_STATE_IDLE && repeater->slot[0].src_id == src_id && repeater->slot[0].dst_id == dst_id && repeater->slot[0].call_type == call_type) ||
			(repeater->slot[1].state != REPEATER_SLOT_STATE_IDLE && repeater->slot[1].src_id == src_id && repeater->slot[1].dst_id == dst_id && repeater->slot[1].call_type == call_type))
				return repeater;

		repeater = repeater->next;
	}
	return NULL;
}

static flag_t repeaters_issnmpignoredforip(struct in_addr *ipaddr) {
	char *ignoredhosts = config_get_ignoredsnmprepeaterhosts();
	char *tok = NULL;
	struct in_addr ignoredaddr;

	tok = strtok(ignoredhosts, ",");
	if (tok) {
		do {
			if (comm_hostname_to_ip(tok, &ignoredaddr)) {
				if (memcmp(&ignoredaddr, ipaddr, sizeof(struct in_addr)) == 0) {
					free(ignoredhosts);
					return 1;
				}
			} else
				console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters: can't resolve hostname %s\n", tok);

			tok = strtok(NULL, ",");
		} while (tok != NULL);
	}
	free(ignoredhosts);
	return 0;
}

static void repeaters_remove(repeater_t *repeater) {
	if (repeater == NULL)
		return;

	console_log("repeaters [%s]: removing\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));

	if (repeater->prev)
		repeater->prev->next = repeater->next;
	if (repeater->next)
		repeater->next->prev = repeater->prev;

	if (repeater == repeaters)
		repeaters = repeater->next;

	free(repeater);
}

repeater_t *repeaters_add(struct in_addr *ipaddr) {
	repeater_t *repeater = repeaters_findbyip(ipaddr);

	if (ipaddr == NULL)
		return NULL;

	if (repeater == NULL) {
		repeater = (repeater_t *)calloc(sizeof(repeater_t), 1);
		if (repeater == NULL) {
			console_log("repeaters [%s]: can't add new repeater, not enough memory\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			return NULL;
		}
		memcpy(&repeater->ipaddr, ipaddr, sizeof(struct in_addr));
		if (repeaters_issnmpignoredforip(ipaddr))
			repeater->snmpignored = 1;

		repeater->slot[0].voicestream = voicestreams_get_stream_for_repeater(ipaddr, 1);
		repeater->slot[1].voicestream = voicestreams_get_stream_for_repeater(ipaddr, 2);

		if (repeaters != NULL) {
			repeaters->prev = repeater;
			repeater->next = repeaters;
		}
		repeaters = repeater;

		console_log("repeaters [%s]: added, snmp ignored: %u ts1 stream: %s ts2 stream: %s\n",
			repeaters_get_display_string_for_ip(&repeater->ipaddr), repeater->snmpignored,
			repeater->slot[0].voicestream != NULL ? repeater->slot[0].voicestream->name : "no stream defined",
			repeater->slot[1].voicestream != NULL ? repeater->slot[1].voicestream->name : "no stream defined");
	}
	repeater->last_active_time = time(NULL);

	return repeater;
}

void repeaters_list(void) {
	repeater_t *repeater = repeaters;
	int i = 1;

	if (repeaters == NULL) {
		console_log("no repeaters found yet\n");
		return;
	}

	console_log("repeaters:\n");
	console_log("      nr              ip     id  callsign  act  lstinf         type        fwver    dlfreq    ulfreq snmp ts1/ts2 streams\n");
	while (repeater) {
		console_log("  #%4u: %15s %6u %9s %4u  %6u %12s %12s %9u %9u    %u %s / %s\n",
			i++,
			comm_get_ip_str(&repeater->ipaddr),
			repeater->id,
			repeater->callsign,
			time(NULL)-repeater->last_active_time,
			time(NULL)-repeater->last_repeaterinfo_request_time,
			repeater->type,
			repeater->fwversion,
			repeater->dlfreq,
			repeater->ulfreq,
			!repeater->snmpignored,
			repeater->slot[0].voicestream != NULL ? repeater->slot[0].voicestream->name : "n/a",
			repeater->slot[1].voicestream != NULL ? repeater->slot[1].voicestream->name : "n/a");

		repeater = repeater->next;
	}
}

void repeaters_state_change(repeater_t *repeater, dmr_timeslot_t timeslot, repeater_slot_state_t new_state) {
	console_log(LOGLEVEL_REPEATERS "repeaters [%s]: slot %u state change from %s to %s\n",
		repeaters_get_display_string_for_ip(&repeater->ipaddr), timeslot+1, repeaters_get_readable_slot_state(repeater->slot[timeslot].state),
		repeaters_get_readable_slot_state(new_state));
	repeater->slot[timeslot].state = new_state;

	if (repeater->auto_rssi_update_enabled_at != 0 &&
		repeater->slot[0].state != REPEATER_SLOT_STATE_CALL_RUNNING &&
		repeater->slot[1].state != REPEATER_SLOT_STATE_CALL_RUNNING) {
			console_log(LOGLEVEL_REPEATERS "repeaters [%s]: stopping auto rssi update\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			repeater->auto_rssi_update_enabled_at = 0;
	}
}

void repeaters_process(void) {
	repeater_t *repeater = repeaters;
	repeater_t *repeater_to_remove;
	struct timeval currtime = {0,};
	struct timeval difftime = {0,};

	while (repeater) {
		if (time(NULL)-repeater->last_active_time > config_get_repeaterinactivetimeoutinsec()) {
			console_log(LOGLEVEL_REPEATERS "repeaters [%s]: timed out\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			repeater_to_remove = repeater;
			repeater = repeater->next;
			repeaters_remove(repeater_to_remove);
			continue;
		}

		if (!repeater->snmpignored && config_get_repeaterinfoupdateinsec() > 0 && time(NULL)-repeater->last_repeaterinfo_request_time > config_get_repeaterinfoupdateinsec()) {
			console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: sending snmp info update request\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			snmp_start_read_repeaterinfo(comm_get_ip_str(&repeater->ipaddr));
			repeater->last_repeaterinfo_request_time = time(NULL);
		}

		if (repeater->slot[0].state == REPEATER_SLOT_STATE_CALL_RUNNING && time(NULL)-repeater->slot[0].last_packet_received_at > config_get_calltimeoutinsec())
			dmr_handle_voicecall_timeout(repeater, 0);

		if (repeater->slot[1].state == REPEATER_SLOT_STATE_CALL_RUNNING && time(NULL)-repeater->slot[1].last_packet_received_at > config_get_calltimeoutinsec())
			dmr_handle_voicecall_timeout(repeater, 0);

		if (repeater->auto_rssi_update_enabled_at > 0 && repeater->auto_rssi_update_enabled_at <= time(NULL)) {
			if (config_get_rssiupdateduringcallinmsec() > 0) {
				gettimeofday(&currtime, NULL);
				timersub(&currtime, &repeater->last_rssi_request_time, &difftime);
				if (difftime.tv_sec*1000+difftime.tv_usec/1000 > config_get_rssiupdateduringcallinmsec()) {
					snmp_start_read_rssi(comm_get_ip_str(&repeater->ipaddr));
					repeater->last_rssi_request_time = currtime;
				}
			}
		}

		if (repeater->slot[0].state == REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING && time(NULL)-repeater->slot[0].data_header_received_at > config_get_datatimeoutinsec())
			dmr_handle_data_timeout(repeater, 0);

		if (repeater->slot[1].state == REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING && time(NULL)-repeater->slot[1].data_header_received_at > config_get_datatimeoutinsec())
			dmr_handle_data_timeout(repeater, 1);

		repeater = repeater->next;
	}
}

void repeaters_deinit(void) {
	console_log("repeaters: deinit\n");

	while (repeaters != NULL)
		repeaters_remove(repeaters);
}
