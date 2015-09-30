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

#include "ipsc-handle.h"

#include <libs/daemon/console.h>
#include <libs/base/dmr-handle.h>
#include <libs/dmrpacket/dmrpacket-sync.h>
#include <libs/voicestreams/voicestreams-process.h>

void ipsc_handle_by_slot_type(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	switch (ipscpacket->slot_type) {
		case IPSCPACKET_SLOT_TYPE_IPSC_SYNC:
			break;
		case IPSCPACKET_SLOT_TYPE_CSBK:
			repeater->slot[ipscpacket->timeslot-1].last_call_or_data_packet_received_at = time(NULL);
			dmr_handle_csbk(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_LC_HEADER:
			dmr_handle_data_call_end(repeater, ipscpacket->timeslot-1);
			repeater->slot[ipscpacket->timeslot-1].last_call_or_data_packet_received_at = time(NULL);
			dmr_handle_voice_lc_header(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_F:
			dmr_handle_data_call_end(repeater, ipscpacket->timeslot-1);
			repeater->slot[ipscpacket->timeslot-1].last_call_or_data_packet_received_at = time(NULL);
			if (repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_VOICE_CALL_RUNNING) {
				// Checking if this call is already running on another repeater. This can happen if dmrshark is running
				// on a server which has multiple repeaters' traffic running through it.
				if (repeaters_get_active(ipscpacket->src_id, ipscpacket->dst_id, ipscpacket->call_type) != NULL)
					return;
				dmr_handle_voice_call_start(ip_packet, ipscpacket, repeater);
			} else {
				if (ipscpacket->src_id != repeater->slot[ipscpacket->timeslot-1].src_id ||
					ipscpacket->dst_id != repeater->slot[ipscpacket->timeslot-1].dst_id ||
					ipscpacket->call_type != repeater->slot[ipscpacket->timeslot-1].call_type) { // Another call started suddenly?
						// Checking if this call is already running on another repeater. This can happen if dmrshark is running
						// on a server which has multiple repeaters' traffic running through it.
						if (repeaters_get_active(ipscpacket->src_id, ipscpacket->dst_id, ipscpacket->call_type) != NULL)
							return;
						dmr_handle_voice_call_start(ip_packet, ipscpacket, repeater);
					}
			}
			dmr_handle_voice_frame(ip_packet, ipscpacket, repeater);
			voicestreams_processpacket(ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_TERMINATOR_WITH_LC:
			dmr_handle_data_call_end(repeater, ipscpacket->timeslot-1);
			dmr_handle_terminator_with_lc(ip_packet, ipscpacket, repeater);
			dmr_handle_voice_call_end(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_DATA_HEADER:
			repeater->slot[ipscpacket->timeslot-1].last_call_or_data_packet_received_at = time(NULL);
			dmr_handle_voice_call_end(ip_packet, ipscpacket, repeater);
			dmr_handle_data_header(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_RATE_34_DATA:
			repeater->slot[ipscpacket->timeslot-1].last_call_or_data_packet_received_at = time(NULL);
			dmr_handle_voice_call_end(ip_packet, ipscpacket, repeater);
			dmr_handle_data_34rate(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_RATE_12_DATA:
			repeater->slot[ipscpacket->timeslot-1].last_call_or_data_packet_received_at = time(NULL);
			dmr_handle_voice_call_end(ip_packet, ipscpacket, repeater);
			dmr_handle_data_12rate(ip_packet, ipscpacket, repeater);
			break;
		default:
			break;
	}
}
