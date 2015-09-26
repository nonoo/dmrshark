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

#include "dmr-handle.h"

#include <libs/daemon/console.h>
#include <libs/remotedb/remotedb.h>
#include <libs/voicestreams/voicestreams-process.h>
#include <libs/dmrpacket/dmrpacket-lc.h>
#include <libs/dmrpacket/dmrpacket-slot-type.h>
#include <libs/dmrpacket/dmrpacket-csbk.h>
#include <libs/dmrpacket/dmrpacket-sync.h>
#include <libs/dmrpacket/dmrpacket-emb.h>
#include <libs/dmrpacket/dmrpacket-data-34rate.h>
#include <libs/base/base.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void dmr_handle_voicecall_end(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	if (repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING)
		return;

	voicestreams_process_call_end(repeater->slot[ipscpacket->timeslot-1].voicestream, repeater);

	console_log(LOGLEVEL_DMR "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: %s call end on ts %u src id %u dst id %u\n",
		repeaters_get_display_string_for_ip(&ip_packet->ip_dst), dmr_get_readable_call_type(repeater->slot[ipscpacket->timeslot-1].call_type),
		ipscpacket->timeslot, repeater->slot[ipscpacket->timeslot-1].src_id, repeater->slot[ipscpacket->timeslot-1].dst_id);
	repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ipscpacket->timeslot-1].call_ended_at = time(NULL);

	remotedb_update(repeater);
	remotedb_update_stats_callend(repeater, ipscpacket->timeslot-1);

	if (repeater->slot[ipscpacket->timeslot-1].echo_buf_first_entry != NULL)
		repeaters_play_and_free_echo_buf(repeater, ipscpacket->timeslot-1);
}

void dmr_handle_voicecall_start(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	if (repeater->slot[ipscpacket->timeslot-1].state == REPEATER_SLOT_STATE_CALL_RUNNING)
		dmr_handle_voicecall_end(ip_packet, ipscpacket, repeater);

	console_log(LOGLEVEL_DMR "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: %s call start on ts %u src id %u dst id %u\n",
		repeaters_get_display_string_for_ip(&ip_packet->ip_dst), dmr_get_readable_call_type(ipscpacket->call_type), ipscpacket->timeslot, ipscpacket->src_id, ipscpacket->dst_id);
	repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_CALL_RUNNING);
	repeater->slot[ipscpacket->timeslot-1].call_started_at = time(NULL);
	repeater->slot[ipscpacket->timeslot-1].call_ended_at = 0;
	repeater->slot[ipscpacket->timeslot-1].call_type = ipscpacket->call_type;
	repeater->slot[ipscpacket->timeslot-1].dst_id = ipscpacket->dst_id;
	repeater->slot[ipscpacket->timeslot-1].src_id = ipscpacket->src_id;
	repeater->slot[ipscpacket->timeslot-1].rssi = repeater->slot[ipscpacket->timeslot-1].avg_rssi = 0;

	if (repeater->auto_rssi_update_enabled_at == 0 && !repeater->snmpignored) {
		console_log(LOGLEVEL_SNMP "snmp [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
		console_log(LOGLEVEL_SNMP "->%s]: starting auto repeater status update\n", repeaters_get_display_string_for_ip(&ip_packet->ip_dst));
		repeater->auto_rssi_update_enabled_at = time(NULL)+1; // +1 - lets add a little delay to let the repeater read the correct RSSI.
	}

	voicestreams_process_call_start(repeater->slot[ipscpacket->timeslot-1].voicestream, repeater);

	repeaters_free_echo_buf(repeater, ipscpacket->timeslot-1);

	remotedb_update(repeater);
	remotedb_update_repeater(repeater);
}

void dmr_handle_voicecall_timeout(repeater_t *repeater, dmr_timeslot_t ts) {
	if (repeater == NULL)
		return;

	voicestreams_process_call_end(repeater->slot[ts].voicestream, repeater);
	console_log(LOGLEVEL_DMR "dmr [%s]: call timeout on ts%u\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ts+1);
	repeaters_state_change(repeater, ts, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ts].call_ended_at = time(NULL);

	remotedb_update(repeater);
	remotedb_update_repeater(repeater);
	remotedb_update_stats_callend(repeater, ts);

	if (repeater->slot[ts].echo_buf_first_entry != NULL)
		repeaters_play_and_free_echo_buf(repeater, ts);
}

void dmr_handle_data_timeout(repeater_t *repeater, dmr_timeslot_t ts) {
	if (repeater == NULL)
		return;

	console_log(LOGLEVEL_DMR "dmr [%s]: data timeout on ts%u\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ts);
	repeaters_state_change(repeater, ts, REPEATER_SLOT_STATE_IDLE);
}

void dmr_handle_voice_lc_header(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;

	if (ipscpacket == NULL)
		return;

	console_log(LOGLEVEL_DMRLC "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMRLC "->%s]: ts%u got voice lc header: ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst), ipscpacket->timeslot);

	console_log(LOGLEVEL_DMRLC "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_extract_bits(&ipscpacket->payload_bits))));
	dmrpacket_slot_type_decode(dmrpacket_slot_type_extract_bits(&ipscpacket->payload_bits));
	packet_payload_info_bits = dmrpacket_extract_info_bits(&ipscpacket->payload_bits);
	packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
	dmrpacket_lc_decode_voice_lc_header(bptc_196_96_extractdata(packet_payload_info_bits->bits));
}

void dmr_handle_terminator_with_lc(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;

	if (ipscpacket == NULL)
		return;

	console_log(LOGLEVEL_DMRLC "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMRLC "->%s]: ts%u got terminator with lc: ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst), ipscpacket->timeslot);

	console_log(LOGLEVEL_DMRLC "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_extract_bits(&ipscpacket->payload_bits))));
	dmrpacket_slot_type_decode(dmrpacket_slot_type_extract_bits(&ipscpacket->payload_bits));
	packet_payload_info_bits = dmrpacket_extract_info_bits(&ipscpacket->payload_bits);
	packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
	dmrpacket_lc_decode_terminator_with_lc(bptc_196_96_extractdata(packet_payload_info_bits->bits));
}

void dmr_handle_csbk(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;

	if (ipscpacket == NULL)
		return;

	console_log(LOGLEVEL_DMRLC "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMRLC "->%s]: ts%u got csbk: ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst), ipscpacket->timeslot);

	console_log(LOGLEVEL_DMRLC "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_extract_bits(&ipscpacket->payload_bits))));
	dmrpacket_slot_type_decode(dmrpacket_slot_type_extract_bits(&ipscpacket->payload_bits));
	packet_payload_info_bits = dmrpacket_extract_info_bits(&ipscpacket->payload_bits);
	packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
	dmrpacket_csbk_decode(bptc_196_96_extractdata(packet_payload_info_bits->bits));
}

void dmr_handle_voice_frame(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_sync_bits_t *sync_bits;
	dmrpacket_sync_pattern_type_t sync_pattern_type;
	dmrpacket_emb_t *emb;
	dmrpacket_emb_signalling_lc_bits_t emb_signalling_lc_bits;

	if (ipscpacket == NULL)
		return;

	console_log(LOGLEVEL_DMRLC "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMRLC "->%s]: ts%u got voice frame: ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst), ipscpacket->timeslot);

	if (repeater->slot[ipscpacket->timeslot-1].dst_id == DMRSHARK_DEFAULT_DMR_ID && repeater->slot[ipscpacket->timeslot-1].src_id != DMRSHARK_DEFAULT_DMR_ID)
		repeaters_store_voice_frame_to_echo_buf(repeater, ipscpacket);

	// Is this frame a sync frame?
	sync_bits = dmrpacket_sync_extract_bits(&ipscpacket->payload_bits);
	sync_pattern_type = dmrpacket_sync_get_sync_pattern_type(sync_bits);
	if (sync_pattern_type != DMRPACKET_SYNC_PATTERN_TYPE_UNKNOWN) {
		console_log(LOGLEVEL_DMRLC "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(sync_pattern_type));
		repeater->slot[ipscpacket->timeslot-1].voice_frame_num = 0;
		return;
	}
	if (repeater->slot[ipscpacket->timeslot-1].voice_frame_num < 5)
		repeater->slot[ipscpacket->timeslot-1].voice_frame_num++;
	else {
		console_log(LOGLEVEL_DMRLC "unexpected non-sync voice frame\n");
		return;
	}

	switch (repeater->slot[ipscpacket->timeslot-1].voice_frame_num) {
		case 0: console_log(LOGLEVEL_DMRLC "a\n"); break;
		case 1: console_log(LOGLEVEL_DMRLC "b\n"); break;
		case 2: console_log(LOGLEVEL_DMRLC "c\n"); break;
		case 3: console_log(LOGLEVEL_DMRLC "d\n"); break;
		case 4: console_log(LOGLEVEL_DMRLC "e\n"); break;
		case 5: console_log(LOGLEVEL_DMRLC "f\n"); break;
		default:
			return;
	}

	// If it's not a sync frame, then it should have an EMB inside the sync field.
	emb = dmrpacket_emb_decode(dmrpacket_emb_extract_from_sync(sync_bits));
	if (emb == NULL)
		return;

	// Handling embedded signalling LC.
	if (emb->lcss == DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT) {
		if (dmrpacket_emb_is_null_fragment(dmrpacket_emb_signalling_lc_fragment_extract_from_sync(sync_bits)))
			console_log(LOGLEVEL_DMRLC "  received null fragment\n");
		else
			console_log(LOGLEVEL_DMRLC "  received unknown single fragment\n");
		return;
	}

	if (emb->lcss == DMRPACKET_EMB_LCSS_FIRST_FRAGMENT) {
		console_log(LOGLEVEL_DMRLC "  got first lc fragment\n");
		vbptc_16_11_clear(&repeater->slot[ipscpacket->timeslot-1].emb_sig_lc_vbptc_storage);
	}

	if (emb->lcss == DMRPACKET_EMB_LCSS_FIRST_FRAGMENT ||
		emb->lcss == DMRPACKET_EMB_LCSS_CONTINUATION ||
		emb->lcss == DMRPACKET_EMB_LCSS_LAST_FRAGMENT) {
			if (vbptc_16_11_add_burst(&repeater->slot[ipscpacket->timeslot-1].emb_sig_lc_vbptc_storage,
				(flag_t *)dmrpacket_emb_signalling_lc_fragment_extract_from_sync(sync_bits), sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t))) {
					console_log(LOGLEVEL_DMRLC "  added lc fragment to the storage\n");
			} else
				console_log(LOGLEVEL_DMRLC "  storage full, can't add lc fragment\n");
	}

	if (emb->lcss == DMRPACKET_EMB_LCSS_LAST_FRAGMENT) {
		console_log(LOGLEVEL_DMRLC "  got last lc fragment\n");
		if (vbptc_16_11_check_and_repair(&repeater->slot[ipscpacket->timeslot-1].emb_sig_lc_vbptc_storage)) {
			vbptc_16_11_get_data_bits(&repeater->slot[ipscpacket->timeslot-1].emb_sig_lc_vbptc_storage, (flag_t *)&emb_signalling_lc_bits, sizeof(dmrpacket_emb_signalling_lc_bits_t));

			console_log(LOGLEVEL_DMRLC "  decoding embedded signalling lc:\n");
			dmrpacket_lc_decode_emb_signalling_lc(dmrpacket_emb_signalling_lc_deinterleave(&emb_signalling_lc_bits));
		}
		vbptc_16_11_clear(&repeater->slot[ipscpacket->timeslot-1].emb_sig_lc_vbptc_storage);
	}
}

void dmr_handle_data_header(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_header_t *data_packet_header = NULL;
	dmrpacket_data_header_responsetype_t data_response_type = DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;

	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	console_log(LOGLEVEL_DMR "dmr data [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: got header\n", repeaters_get_display_string_for_ip(&ip_packet->ip_dst));

	data_packet_header = dmrpacket_data_header_decode(dmrpacket_data_extract_and_repair_bptc_data(&ipscpacket->payload_bits), 0);

	if (data_packet_header == NULL)
		return;

	repeater->slot[ipscpacket->timeslot-1].data_blocks_received = 0;
	memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
	repeater->slot[ipscpacket->timeslot-1].data_header_received_at = time(NULL);

	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_RESPONSE) {
		data_response_type = dmrpacket_data_header_decode_response(data_packet_header);
		console_log(LOGLEVEL_DMRDATA "  response type: %s\n", dmrpacket_data_header_get_readable_response_type(data_response_type));
	}

	memcpy(&repeater->slot[ipscpacket->timeslot-1].data_packet_header, data_packet_header, sizeof(dmrpacket_data_header_t));
	repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING);
}

static void dmr_handle_data_fragment_assembly_for_short_data_defined(ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_fragment_t *data_fragment = NULL;
	char *msg = NULL;

	// Got all blocks?
	if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.appended_blocks == repeater->slot[ipscpacket->timeslot-1].data_blocks_received) {
		repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_IDLE);

		data_fragment = dmrpacket_data_extract_fragment_from_blocks(repeater->slot[ipscpacket->timeslot-1].data_blocks,
			min(sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks)/sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks[0]), repeater->slot[ipscpacket->timeslot-1].data_blocks_received));
		msg = dmrpacket_data_convertmsg(data_fragment, repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.dd_format);
		if (msg && isprint(msg[0]))
			console_log(LOGLEVEL_DMR "  decoded sms: %s\n", msg); // TODO: upload decoded message to remotedb
	}
}

void dmr_handle_data_34rate(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	dmrpacket_data_34rate_dibits_t *packet_payload_dibits = NULL;
	dmrpacket_data_34rate_constellationpoints_t *packet_payload_constellationpoints = NULL;
	dmrpacket_data_34rate_tribits_t *packet_payload_tribits = NULL;
	dmrpacket_data_binary_t *data_binary = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL ||
		repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING)
		return;

	console_log(LOGLEVEL_DMR "dmr data [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: got 3/4 rate block #%u/%u \n", repeaters_get_display_string_for_ip(&ip_packet->ip_dst),
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

	// Now we only care about short data packets.
	if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED)
		dmr_handle_data_fragment_assembly_for_short_data_defined(ipscpacket, repeater);
}

void dmr_handle_data_12rate(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL ||
		repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING)
		return;

	console_log(LOGLEVEL_DMR "dmr data [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: got 1/2 rate block #%u/%u \n", repeaters_get_display_string_for_ip(&ip_packet->ip_dst),
		repeater->slot[ipscpacket->timeslot-1].data_blocks_received+1, repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

	data_block_bytes = dmrpacket_data_convert_payload_bptc_data_bits_to_block_bytes(dmrpacket_data_extract_and_repair_bptc_data(&ipscpacket->payload_bits));
	data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested);

	if (data_block) {
		// Storing the block if serialnr is in bounds.
		if (data_block->serialnr < sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks)/sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks[0]))
			memcpy(&repeater->slot[ipscpacket->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
	}
	repeater->slot[ipscpacket->timeslot-1].data_blocks_received++;

	// Now we only care about short data packets.
	if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED)
		dmr_handle_data_fragment_assembly_for_short_data_defined(ipscpacket, repeater);
}
