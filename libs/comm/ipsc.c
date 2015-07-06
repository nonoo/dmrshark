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

#include "ipscpacket.h"
#include "comm.h"

#include <libs/base/log.h>
#include <libs/remotedb/remotedb.h>
#include <libs/dmrpacket/dmrpacket.h>
#include <libs/coding/bptc-196-96.h>

#include <netinet/udp.h>
#include <string.h>

#define HEARTBEAT_PERIOD_IN_SEC 6

static void ipsc_call_end(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING)
		return;

	console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_IPSC "->%s]: %s call end on ts %u src id %u dst id %u\n",
	comm_get_ip_str(&ip_packet->ip_dst), dmr_get_readable_call_type(repeater->slot[ipsc_packet->timeslot-1].call_type),
		ipsc_packet->timeslot, repeater->slot[ipsc_packet->timeslot-1].src_id, repeater->slot[ipsc_packet->timeslot-1].dst_id);
	repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ipsc_packet->timeslot-1].call_ended_at = time(NULL);

	remotedb_update(repeater);
	remotedb_update_stats_callend(repeater, ipsc_packet->timeslot-1);
}

static void ipsc_call_start(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	if (repeater->slot[ipsc_packet->timeslot-1].state == REPEATER_SLOT_STATE_CALL_RUNNING)
		ipsc_call_end(ip_packet, ipsc_packet, repeater);

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

static bptc_196_96_data_bits_t *ipscpacket_get_bptc_data(dmrpacket_payload_bits_t *packet_payload_bits) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;

	packet_payload_info_bits = dmrpacket_extractinfobits(packet_payload_bits);
	packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
	bptc_196_96_check_and_repair(packet_payload_info_bits->bits);
	return bptc_196_96_extractdata(packet_payload_info_bits->bits);
}

static void ipsc_handle_data_header(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_data_header_t *data_packet_header = NULL;
	dmrpacket_data_header_responsetype_t data_response_type = DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;

	console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_IPSC "->%s]: got data header\n", comm_get_ip_str(&ip_packet->ip_dst));

	packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet->payload);
	data_packet_header = dmrpacket_data_header_decode(ipscpacket_get_bptc_data(packet_payload_bits), 0);

	repeater->slot[ipsc_packet->timeslot-1].data_blocks_received = 0;
	memset(repeater->slot[ipsc_packet->timeslot-1].data_blocks, 0, sizeof(dmrpacket_data_block_t)*sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks));
	repeater->slot[ipsc_packet->timeslot-1].data_header_received_at = time(NULL);

	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_RESPONSE) {
		data_response_type = dmrpacket_data_header_decode_response(data_packet_header);
		console_log("  response type: %s\n", dmrpacket_data_header_get_readable_response_type(data_response_type));
	}
	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		memcpy(&repeater->slot[ipsc_packet->timeslot-1].data_packet_header, data_packet_header, sizeof(dmrpacket_data_header_t));
		repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING);
	}
}

static void ipsc_handle_data_fragment_assembly_for_short_data_defined(ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_data_fragment_t *data_fragment = NULL;
	char *msg = NULL;

	// Got all blocks?
	if (repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.appended_blocks == repeater->slot[ipsc_packet->timeslot-1].data_blocks_received) {
		repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_IDLE);
		data_fragment = dmrpacket_data_extract_fragment_from_blocks(repeater->slot[ipsc_packet->timeslot-1].data_blocks,
			min(sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks)/sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks[0]), repeater->slot[ipsc_packet->timeslot-1].data_blocks_received));
		msg = dmrpacket_data_convertmsg(data_fragment, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.dd_format);
		if (msg)
			console_log("  decoded message: %s\n", msg);
	}
}

static void ipsc_handle_data_34rate(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	dmrpacket_data_34rate_dibits_t *packet_payload_dibits = NULL;
	dmrpacket_data_34rate_constellationpoints_t *packet_payload_constellationpoints = NULL;
	dmrpacket_data_34rate_tribits_t *packet_payload_tribits = NULL;
	dmrpacket_data_binary_t *data_binary = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING) // Data without a previously received header?
		return;

	if (repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_IPSC "->%s]: got 3/4 rate data block #%u/%u \n", comm_get_ip_str(&ip_packet->ip_dst),
			repeater->slot[ipsc_packet->timeslot-1].data_blocks_received+1, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

		packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet->payload);
		packet_payload_info_bits = dmrpacket_extractinfobits(packet_payload_bits);
		packet_payload_dibits = dmrpacket_data_34rate_extract_dibits(packet_payload_info_bits);
		packet_payload_dibits = dmrpacket_data_34rate_deinterleave_dibits(packet_payload_dibits);
		packet_payload_constellationpoints = dmrpacket_data_34rate_getconstellationpoints(packet_payload_dibits);
		packet_payload_tribits = dmrpacket_data_34rate_extract_tribits(packet_payload_constellationpoints);
		data_binary = dmrpacket_data_34rate_extract_binary(packet_payload_tribits);
		data_block_bytes = dmrpacket_data_convert_binary_to_block_bytes(data_binary);
		data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_34_DATA_CONTINUATION, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.response_requested);

		if (data_block) {
			// Storing the block if serialnr is in bounds.
			if (data_block->serialnr < sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks)/sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks[0]))
				memcpy(&repeater->slot[ipsc_packet->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
		}
		repeater->slot[ipsc_packet->timeslot-1].data_blocks_received++;

		ipsc_handle_data_fragment_assembly_for_short_data_defined(ipsc_packet, repeater);
	}
}

static void ipsc_handle_data_12rate(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING) // Data without a previously received header?
		return;

	if (repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_IPSC "->%s]: got 1/2 rate data block #%u/%u \n", comm_get_ip_str(&ip_packet->ip_dst),
			repeater->slot[ipsc_packet->timeslot-1].data_blocks_received+1, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

		packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet->payload);
		data_block_bytes = dmrpacket_data_convert_payload_bptc_data_bits_to_block_bytes(ipscpacket_get_bptc_data(packet_payload_bits));
		data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.response_requested);

		if (data_block) {
			// Storing the block if serialnr is in bounds.
			if (data_block->serialnr < sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks)/sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks[0]))
				memcpy(&repeater->slot[ipsc_packet->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
		}
		repeater->slot[ipsc_packet->timeslot-1].data_blocks_received++;

		ipsc_handle_data_fragment_assembly_for_short_data_defined(ipsc_packet, repeater);
	}
}

static void ipscpacket_handle_control_packet(dmrpacket_sync_type_t payload_sync_type, dmrpacket_payload_bits_t *packet_payload_bits) {
	dmrpacket_payload_slot_type_bits_t *payload_slot_type_bits = NULL;
	dmrpacket_payload_slot_type_t *payload_slot_type = NULL;
	union {
		dmrpacket_control_full_lc_t *full_lc;
	} control_packet;

	switch (payload_sync_type) {
		default:
			break;
		case DMRPACKET_SYNC_TYPE_BS_SOURCED_DATA:
		case DMRPACKET_SYNC_TYPE_MS_SOURCED_DATA:
		case DMRPACKET_SYNC_TYPE_MS_SOURCED_RC:
		case DMRPACKET_SYNC_TYPE_DIRECT_DATA_TS1:
		case DMRPACKET_SYNC_TYPE_DIRECT_DATA_TS2:
			// A packet with a data or control sync pattern also has a slot type field.
			payload_slot_type_bits = dmrpacket_extractslottypebits(packet_payload_bits);
			payload_slot_type = dmrpacket_decode_slot_type(payload_slot_type_bits);
			if (payload_slot_type != NULL) {
				console_log(LOGLEVEL_COMM_DMR "  cc: %u slot type: %s\n", payload_slot_type->cc, dmrpacket_data_get_readable_data_type(payload_slot_type->data_type));

				switch (payload_slot_type->data_type) {
					case DMRPACKET_DATA_TYPE_VOICE_LC_HEADER:
						control_packet.full_lc = dmrpacket_control_decode_full_lc(ipscpacket_get_bptc_data(packet_payload_bits));
						break;
					case DMRPACKET_DATA_TYPE_PI_HEADER:
					case DMRPACKET_DATA_TYPE_TERMINATOR_WITH_LC:
					case DMRPACKET_DATA_TYPE_CSBK:
					case DMRPACKET_DATA_TYPE_MBC_HEADER:
					case DMRPACKET_DATA_TYPE_MBC_CONTINUATION:
					case DMRPACKET_DATA_TYPE_DATA_HEADER:
					case DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION:
						// TODO
						break;
					case DMRPACKET_DATA_TYPE_RATE_34_DATA_CONTINUATION:
					case DMRPACKET_DATA_TYPE_IDLE:
					default:
						break;
				}
			}
	}
}

void ipsc_processpacket(struct ip *ip_packet, uint16_t length) {
	uint8_t *packet = (uint8_t *)ip_packet;
	struct udphdr *udp_packet = NULL;
	int ip_header_length = 0;
	ipscpacket_t ipsc_packet = {0,};
	repeater_t *repeater = NULL;
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_payload_sync_bits_t *payload_sync_bits = NULL;
	dmrpacket_sync_type_t payload_sync_type;

	console_log(LOGLEVEL_COMM_IP "  src: %s\n", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM_IP "  dst: %s\n", comm_get_ip_str(&ip_packet->ip_dst));
	ip_header_length = ip_packet->ip_hl*4; // http://www.governmentsecurity.org/forum/topic/16447-calculate-ip-size/
	console_log(LOGLEVEL_COMM_IP "  ip header length: %u\n", ip_header_length);
	if (ip_packet->ip_sum != comm_calcipheaderchecksum(ip_packet, ip_header_length)) {
		console_log(LOGLEVEL_COMM_IP "  ip checksum mismatch, dropping\n");
		return;
	}
	packet += ip_header_length;

	udp_packet = (struct udphdr *)packet;
	console_log(LOGLEVEL_COMM_IP "  srcport: %u\n", ntohs(udp_packet->source));
	console_log(LOGLEVEL_COMM_IP "  dstport: %u\n", ntohs(udp_packet->dest));
	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	console_log(LOGLEVEL_COMM_IP "  length: %u\n", ntohs(udp_packet->len)-sizeof(struct udphdr));
	if (length-ip_header_length != ntohs(udp_packet->len)) {
		console_log(LOGLEVEL_COMM_IP "  udp length not equal to received packet length, dropping\n");
		return;
	}

	if (udp_packet->check != comm_calcudpchecksum(ip_packet, ip_packet->ip_hl*4, udp_packet)) {
		console_log(LOGLEVEL_COMM_IP "  udp checksum mismatch, dropping\n");
		return;
	}

	if (ipscpacket_decode(udp_packet, &ipsc_packet)) {
		console_log(LOGLEVEL_COMM_DMR "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM_DMR "->%s]: decoded dmr packet type: %s (0x%.2x) ts %u slot type: %s (0x%.4x) frame type: %s (0x%.4x) call type: %s (0x%.2x) dstid %u srcid %u\n",
			comm_get_ip_str(&ip_packet->ip_dst),
			ipscpacket_get_readable_packet_type(ipsc_packet.packet_type), ipsc_packet.packet_type,
			ipsc_packet.timeslot,
			ipscpacket_get_readable_slot_type(ipsc_packet.slot_type), ipsc_packet.slot_type,
			ipscpacket_get_readable_frame_type(ipsc_packet.frame_type), ipsc_packet.frame_type,
			dmr_get_readable_call_type(ipsc_packet.call_type), ipsc_packet.call_type,
			ipsc_packet.dst_id,
			ipsc_packet.src_id);

		// The packet is for us?
		if (comm_is_our_ipaddr(&ip_packet->ip_dst))
			repeater = repeaters_add(&ip_packet->ip_src);

		// The packet is for us, or from a listed repeater?
		if (repeater != NULL || (repeater = repeaters_findbyip(&ip_packet->ip_src)) != NULL) {
			if (ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_A ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_B ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_C ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_D ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_E) {
					if (repeater->slot[ipsc_packet.timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING)
						ipsc_call_start(ip_packet, &ipsc_packet, repeater);
					else { // Call running?
						if (ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_CALL_END)
							ipsc_call_end(ip_packet, &ipsc_packet, repeater);
						else { // Another call started suddenly?
							if (ipsc_packet.src_id != repeater->slot[ipsc_packet.timeslot-1].src_id ||
								ipsc_packet.dst_id != repeater->slot[ipsc_packet.timeslot-1].dst_id ||
								ipsc_packet.call_type != repeater->slot[ipsc_packet.timeslot-1].call_type)
									ipsc_call_start(ip_packet, &ipsc_packet, repeater);
						}
					}

					repeater->slot[ipsc_packet.timeslot-1].last_packet_received_at = time(NULL);
			}

			// The data header and voice burst A must contain a sync pattern, so we are looking for it.
			packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet.payload);
			payload_sync_bits = dmrpacket_extractsyncbits(packet_payload_bits);
			payload_sync_type = dmrpacket_get_sync_type(payload_sync_bits);
			if (payload_sync_type != DMRPACKET_SYNC_TYPE_UNKNOWN) {
				console_log(LOGLEVEL_COMM_DMR "  packet has sync: %s\n", dmrpacket_get_readable_sync_type(payload_sync_type));
				ipscpacket_handle_control_packet(payload_sync_type, packet_payload_bits);
			}

			switch (ipsc_packet.slot_type) {
				case IPSCPACKET_SLOT_TYPE_DATA_HEADER:
					ipsc_call_end(ip_packet, &ipsc_packet, repeater);
					ipsc_handle_data_header(ip_packet, &ipsc_packet, repeater);
					break;
				case IPSCPACKET_SLOT_TYPE_3_4_RATE_DATA:
					ipsc_call_end(ip_packet, &ipsc_packet, repeater);
					ipsc_handle_data_34rate(ip_packet, &ipsc_packet, repeater);
					break;
				case IPSCPACKET_SLOT_TYPE_1_2_RATE_DATA:
					ipsc_call_end(ip_packet, &ipsc_packet, repeater);
					ipsc_handle_data_12rate(ip_packet, &ipsc_packet, repeater);
					break;
				default:
					break;
			}
		}
	}

	if (ipscpacket_heartbeat_decode(udp_packet)) {
		if (comm_is_our_ipaddr(&ip_packet->ip_dst)) {
			console_log(LOGLEVEL_HEARTBEAT "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
			console_log(LOGLEVEL_HEARTBEAT "->%s]: got heartbeat\n", comm_get_ip_str(&ip_packet->ip_dst));
			repeater = repeaters_findbyip(&ip_packet->ip_src);
			if (repeater == NULL)
				repeater = repeaters_add(&ip_packet->ip_src);
			else if (time(NULL)-repeater->last_active_time > HEARTBEAT_PERIOD_IN_SEC/2) {
				repeater->last_active_time = time(NULL);
				remotedb_update_repeater_lastactive(repeater);
			}
		}
	}
}
