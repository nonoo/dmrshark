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

#include "ipsc-handle.h"
#include "ipsc-data.h"

#include <libs/daemon/console.h>
#include <libs/base/dmr-handle.h>
#include <libs/dmrpacket/dmrpacket.h>

static void ipsc_handle_slot_type(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	switch (ipscpacket->slot_type) {
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E:
		case IPSCPACKET_SLOT_TYPE_CALL_START:
		case IPSCPACKET_SLOT_TYPE_CALL_END:
			if (repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING) {
				// Checking if this call is already running on another repeater. This can happen if dmrshark is running
				// on a server which has multiple repeaters' traffic running through it.
				if (repeaters_get_active(ipscpacket->src_id, ipscpacket->dst_id, ipscpacket->call_type) != NULL)
					return;
				dmr_handle_voicecall_start(ip_packet, ipscpacket, repeater);
			} else {
				if (ipscpacket->slot_type == IPSCPACKET_SLOT_TYPE_CALL_END)
					dmr_handle_voicecall_end(ip_packet, ipscpacket, repeater);
				else {
					if (ipscpacket->src_id != repeater->slot[ipscpacket->timeslot-1].src_id ||
						ipscpacket->dst_id != repeater->slot[ipscpacket->timeslot-1].dst_id ||
						ipscpacket->call_type != repeater->slot[ipscpacket->timeslot-1].call_type) { // Another call started suddenly?
							// Checking if this call is already running on another repeater. This can happen if dmrshark is running
							// on a server which has multiple repeaters' traffic running through it.
							if (repeaters_get_active(ipscpacket->src_id, ipscpacket->dst_id, ipscpacket->call_type) != NULL)
								return;
							dmr_handle_voicecall_start(ip_packet, ipscpacket, repeater);
						}
				}
			}

			repeater->slot[ipscpacket->timeslot-1].last_packet_received_at = time(NULL);
			break;
		case IPSCPACKET_SLOT_TYPE_DATA_HEADER:
			dmr_handle_voicecall_end(ip_packet, ipscpacket, repeater);
			ipsc_data_handle_header(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_3_4_RATE_DATA:
			dmr_handle_voicecall_end(ip_packet, ipscpacket, repeater);
			ipsc_data_handle_34rate(ip_packet, ipscpacket, repeater);
			break;
		case IPSCPACKET_SLOT_TYPE_1_2_RATE_DATA:
			dmr_handle_voicecall_end(ip_packet, ipscpacket, repeater);
			ipsc_data_handle_12rate(ip_packet, ipscpacket, repeater);
			break;
		default:
			break;
	}
}

static void ipsc_handle_sync_field(dmrpacket_payload_bits_t *packet_payload_bits) {
	dmrpacket_sync_pattern_type_t sync_pattern_type = dmrpacket_get_sync_pattern_type(dmrpacket_extract_sync_field_bits(packet_payload_bits));
	if (sync_pattern_type != DMRPACKET_SYNC_PATTERN_TYPE_UNKNOWN)
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  sync pattern type: %s\n", dmrpacket_get_readable_sync_pattern_type(sync_pattern_type));
}

void ipsc_handle(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	ipsc_handle_sync_field(&ipscpacket->payload_bits);
	ipsc_handle_slot_type(ip_packet, ipscpacket, repeater);
}
