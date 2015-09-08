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

#include "dmrlog.h"
#include "base.h"

#include <libs/daemon/console.h>
#include <libs/comm/comm.h>
#include <libs/remotedb/remotedb.h>

void dmrlog_voicecall_end(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING)
		return;

	console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_IPSC "->%s]: %s call end on ts %u src id %u dst id %u\n",
	comm_get_ip_str(&ip_packet->ip_dst), dmr_get_readable_call_type(repeater->slot[ipsc_packet->timeslot-1].call_type),
		ipsc_packet->timeslot, repeater->slot[ipsc_packet->timeslot-1].src_id, repeater->slot[ipsc_packet->timeslot-1].dst_id);
	repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ipsc_packet->timeslot-1].call_ended_at = time(NULL);

	remotedb_update(repeater);
	remotedb_update_stats_callend(repeater, ipsc_packet->timeslot);
}

void dmrlog_voicecall_start(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	if (repeater->slot[ipsc_packet->timeslot-1].state == REPEATER_SLOT_STATE_CALL_RUNNING)
		dmrlog_voicecall_end(ip_packet, ipsc_packet, repeater);

	console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_IPSC "->%s]: %s call start on ts %u src id %u dst id %u\n",
		comm_get_ip_str(&ip_packet->ip_dst), dmr_get_readable_call_type(ipsc_packet->call_type), ipsc_packet->timeslot, ipsc_packet->src_id, ipsc_packet->dst_id);
	repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_CALL_RUNNING);
	repeater->slot[ipsc_packet->timeslot-1].call_started_at = time(NULL);
	repeater->slot[ipsc_packet->timeslot-1].call_ended_at = 0;
	repeater->slot[ipsc_packet->timeslot-1].call_type = ipsc_packet->call_type;
	repeater->slot[ipsc_packet->timeslot-1].dst_id = ipsc_packet->dst_id;
	repeater->slot[ipsc_packet->timeslot-1].src_id = ipsc_packet->src_id;
	repeater->slot[ipsc_packet->timeslot-1].rssi = repeater->slot[ipsc_packet->timeslot-1].avg_rssi = 0;

	if (repeater->auto_rssi_update_enabled_at == 0 && !repeater->snmpignored) {
		console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_IPSC "->%s]: starting auto snmp rssi update\n", comm_get_ip_str(&ip_packet->ip_dst));
		repeater->auto_rssi_update_enabled_at = time(NULL)+1; // +1 - lets add a little delay to let the repeater read the correct RSSI.
	}

	remotedb_update(repeater);
}
