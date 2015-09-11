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

#include "ipsc-data.h"
#include "comm.h"

#include <libs/daemon/console.h>

#include <string.h>

void ipsc_data_handle_header(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_header_t *data_packet_header = NULL;
	dmrpacket_data_header_responsetype_t data_response_type = DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;

	console_log(LOGLEVEL_IPSC "ipsc data [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_IPSC "->%s]: got header\n", comm_get_ip_str(&ip_packet->ip_dst));

	data_packet_header = dmrpacket_data_header_decode(dmrpacket_data_extract_and_repair_bptc_data(&ipscpacket->payload_bits), 0);

	if (data_packet_header == NULL)
		return;

	repeater->slot[ipscpacket->timeslot-1].data_blocks_received = 0;
	memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(dmrpacket_data_block_t)*sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
	repeater->slot[ipscpacket->timeslot-1].data_header_received_at = time(NULL);

	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_RESPONSE) {
		data_response_type = dmrpacket_data_header_decode_response(data_packet_header);
		console_log("  response type: %s\n", dmrpacket_data_header_get_readable_response_type(data_response_type));
	}
	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		// TODO: handling other data types
		memcpy(&repeater->slot[ipscpacket->timeslot-1].data_packet_header, data_packet_header, sizeof(dmrpacket_data_header_t));
		repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING);
	}
}

static void ipsc_data_handle_fragment_assembly_for_short_data_defined(ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_fragment_t *data_fragment = NULL;
	char *msg = NULL;

	// Got all blocks?
	if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.appended_blocks == repeater->slot[ipscpacket->timeslot-1].data_blocks_received) {
		repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_IDLE);
		data_fragment = dmrpacket_data_extract_fragment_from_blocks(repeater->slot[ipscpacket->timeslot-1].data_blocks,
			min(sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks)/sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks[0]), repeater->slot[ipscpacket->timeslot-1].data_blocks_received));
		msg = dmrpacket_data_convertmsg(data_fragment, repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.dd_format);
		if (msg)
			console_log("  decoded message: %s\n", msg); // TODO: upload decoded message to remotedb
	}
}

void ipsc_data_handle_34rate(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	dmrpacket_data_34rate_dibits_t *packet_payload_dibits = NULL;
	dmrpacket_data_34rate_constellationpoints_t *packet_payload_constellationpoints = NULL;
	dmrpacket_data_34rate_tribits_t *packet_payload_tribits = NULL;
	dmrpacket_data_binary_t *data_binary = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING) // Data without a previously received header?
		return;

	if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		console_log(LOGLEVEL_IPSC "ipsc data [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_IPSC "->%s]: got 3/4 rate block #%u/%u \n", comm_get_ip_str(&ip_packet->ip_dst),
			repeater->slot[ipscpacket->timeslot-1].data_blocks_received+1, repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

		packet_payload_info_bits = dmrpacket_extract_info_bits(&ipscpacket->payload_bits);
		packet_payload_dibits = dmrpacket_data_34rate_extract_dibits(packet_payload_info_bits);
		packet_payload_dibits = dmrpacket_data_34rate_deinterleave_dibits(packet_payload_dibits);
		packet_payload_constellationpoints = dmrpacket_data_34rate_getconstellationpoints(packet_payload_dibits);
		packet_payload_tribits = dmrpacket_data_34rate_extract_tribits(packet_payload_constellationpoints);
		data_binary = dmrpacket_data_34rate_extract_binary(packet_payload_tribits);
		data_block_bytes = dmrpacket_data_convert_binary_to_block_bytes(data_binary);
		data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_34_DATA_CONTINUATION, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested);

		if (data_block) {
			// Storing the block if serialnr is in bounds.
			if (data_block->serialnr < sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks)/sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks[0]))
				memcpy(&repeater->slot[ipscpacket->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
		}
		repeater->slot[ipscpacket->timeslot-1].data_blocks_received++;

		ipsc_data_handle_fragment_assembly_for_short_data_defined(ipscpacket, repeater);
	}
}

void ipsc_data_handle_12rate(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING) // Data without a previously received header?
		return;

	if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		console_log(LOGLEVEL_IPSC "ipsc data [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_IPSC "->%s]: got 1/2 rate block #%u/%u \n", comm_get_ip_str(&ip_packet->ip_dst),
			repeater->slot[ipscpacket->timeslot-1].data_blocks_received+1, repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

		data_block_bytes = dmrpacket_data_convert_payload_bptc_data_bits_to_block_bytes(dmrpacket_data_extract_and_repair_bptc_data(&ipscpacket->payload_bits));
		data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested);

		if (data_block) {
			// Storing the block if serialnr is in bounds.
			if (data_block->serialnr < sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks)/sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks[0]))
				memcpy(&repeater->slot[ipscpacket->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
		}
		repeater->slot[ipscpacket->timeslot-1].data_blocks_received++;

		ipsc_data_handle_fragment_assembly_for_short_data_defined(ipscpacket, repeater);
	}
}
