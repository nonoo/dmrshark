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
#include "smstxbuf.h"

#include <libs/daemon/console.h>
#include <libs/remotedb/remotedb.h>
#include <libs/voicestreams/voicestreams-process.h>
#include <libs/dmrpacket/dmrpacket-lc.h>
#include <libs/dmrpacket/dmrpacket-slot-type.h>
#include <libs/dmrpacket/dmrpacket-csbk.h>
#include <libs/dmrpacket/dmrpacket-sync.h>
#include <libs/dmrpacket/dmrpacket-emb.h>
#include <libs/coding/trellis.h>
#include <libs/base/base.h>
#include <libs/comm/comm.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void dmr_handle_voice_call_end(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	if (repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_VOICE_CALL_RUNNING)
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

void dmr_handle_voice_call_start(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	if (repeater->slot[ipscpacket->timeslot-1].state == REPEATER_SLOT_STATE_VOICE_CALL_RUNNING)
		dmr_handle_voice_call_end(ip_packet, ipscpacket, repeater);

	console_log(LOGLEVEL_DMR "dmr [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: %s call start on ts %u src id %u dst id %u\n",
		repeaters_get_display_string_for_ip(&ip_packet->ip_dst), dmr_get_readable_call_type(ipscpacket->call_type), ipscpacket->timeslot, ipscpacket->src_id, ipscpacket->dst_id);
	repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_VOICE_CALL_RUNNING);
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

void dmr_handle_voice_call_timeout(repeater_t *repeater, dmr_timeslot_t ts) {
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

void dmr_handle_data_call_timeout(repeater_t *repeater, dmr_timeslot_t ts) {
	if (repeater == NULL)
		return;

	if (repeater->slot[ts].state != REPEATER_SLOT_STATE_DATA_CALL_RUNNING)
		return;

	console_log(LOGLEVEL_DMR "dmr [%s]: data call timeout on ts%u\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ts+1);
	repeaters_state_change(repeater, ts, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ts].data_packet_header_valid = 0;
}

static void dmr_handle_data_call_start(repeater_t *repeater, ipscpacket_t *ipscpacket) {
	if (repeater == NULL)
		return;

	if (repeater->slot[ipscpacket->timeslot].state == REPEATER_SLOT_STATE_DATA_CALL_RUNNING)
		return;

	repeater->slot[ipscpacket->timeslot-1].dst_id = ipscpacket->dst_id;
	repeater->slot[ipscpacket->timeslot-1].src_id = ipscpacket->src_id;

	console_log(LOGLEVEL_DMR "dmr [%s]: data call started on ts%u\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ipscpacket->timeslot);
	repeaters_state_change(repeater, ipscpacket->timeslot-1, REPEATER_SLOT_STATE_DATA_CALL_RUNNING);
}

void dmr_handle_data_call_end(repeater_t *repeater, dmr_timeslot_t ts) {
	if (repeater == NULL)
		return;

	if (repeater->slot[ts].state != REPEATER_SLOT_STATE_DATA_CALL_RUNNING)
		return;

	console_log(LOGLEVEL_DMR "dmr [%s]: data call ended on ts%u\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ts+1);
	repeaters_state_change(repeater, ts, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ts].data_packet_header_valid = 0;
}

void dmr_handle_data_header(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_header_t *data_packet_header = NULL;
	dmrpacket_data_header_responsetype_t data_response_type = DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;
	smstxbuf_t *smstxbuf_first_entry;

	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL)
		return;

	console_log(LOGLEVEL_DMR "dmr data [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: got header, ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst));

	console_log(LOGLEVEL_DMR "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_extract_bits(&ipscpacket->payload_bits))));
	dmrpacket_slot_type_decode(dmrpacket_slot_type_extract_bits(&ipscpacket->payload_bits));

	data_packet_header = dmrpacket_data_header_decode(dmrpacket_data_extract_and_repair_bptc_data(&ipscpacket->payload_bits), 0);
	if (data_packet_header == NULL)
		return;

	repeater->slot[ipscpacket->timeslot-1].data_packet_header_valid = 0;
	repeater->slot[ipscpacket->timeslot-1].data_blocks_received = 0;
	repeater->slot[ipscpacket->timeslot-1].selective_ack_requests_sent = 0;
	repeater->slot[ipscpacket->timeslot-1].rx_seqnum = 0;

	switch (data_packet_header->common.data_packet_format) {
		case DMRPACKET_DATA_HEADER_DPF_UDT:
			memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
			repeater->slot[ipscpacket->timeslot-1].full_message_block_count = repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = data_packet_header->udt.appended_blocks;
			break;
		case DMRPACKET_DATA_HEADER_DPF_RESPONSE:
			data_response_type = dmrpacket_data_header_decode_response(data_packet_header);
			console_log(LOGLEVEL_DMRDATA "  response type: %s\n", dmrpacket_data_header_get_readable_response_type(data_response_type));

			switch (data_response_type) {
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_ACK: // Got a response for a previously sent SMS by us?
					smstxbuf_first_entry = smstxbuf_get_first_entry();
					if (smstxbuf_first_entry != NULL) {
						if (smstxbuf_first_entry->motorola_tms_sms) {
							console_log(LOGLEVEL_DMR "  got ack for sms tx buffer entry, waiting for the tms ack\n");
							return;
						}

						if (smstxbuf_first_entry->dst_id == data_packet_header->common.src_llid &&
							smstxbuf_first_entry->src_id == data_packet_header->common.dst_llid &&
							((smstxbuf_first_entry->call_type == DMR_CALL_TYPE_GROUP && data_packet_header->common.dst_is_a_group) ||
							 (smstxbuf_first_entry->call_type == DMR_CALL_TYPE_PRIVATE && !data_packet_header->common.dst_is_a_group))) {
							 	console_log(LOGLEVEL_DMR "  got ack for sms tx buffer entry:\n");
							 	smstxbuf_print_entry(smstxbuf_first_entry);
							 	smstxbuf_remove_first_entry();
						} else
							console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  ack is not for us (dst id: %u src id: %u)\n", smstxbuf_first_entry->dst_id, smstxbuf_first_entry->src_id);
					} else
						console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  ack is not for us, sms tx buffer is empty\n");

					dmr_handle_data_call_end(repeater, ipscpacket->timeslot-1);
					return;
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT:
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_PACKET_CRC_FAILED:
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_MEMORY_FULL:
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_FSN_OUT_OF_SEQ:
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_UNDELIVERABLE:
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_PKT_OUT_OF_SEQ:
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_DISALLOWED:
					return;
				case DMRPACKET_DATA_HEADER_RESPONSETYPE_SELECTIVE_ACK:
					if (data_packet_header->common.src_llid == DMRSHARK_DEFAULT_DMR_ID) {
						console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  selective ack is sent by us, ignoring\n");
						return;
					}
					break;
			}
			break;
		case DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA:
			memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
			repeater->slot[ipscpacket->timeslot-1].full_message_block_count = repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = data_packet_header->unconfirmed_data.blocks_to_follow;
			break;
		case DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA:
			if (data_packet_header->confirmed_data.full_message) {
				memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
				repeater->slot[ipscpacket->timeslot-1].full_message_block_count = data_packet_header->confirmed_data.blocks_to_follow;
				repeater->slot[ipscpacket->timeslot-1].rx_seqnum = data_packet_header->confirmed_data.sendseqnum;
			}
			repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = data_packet_header->confirmed_data.blocks_to_follow;
			break;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED:
			if (data_packet_header->short_data_defined.full_message) {
				memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
				repeater->slot[ipscpacket->timeslot-1].full_message_block_count = data_packet_header->short_data_defined.appended_blocks;
			}
			repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = data_packet_header->short_data_defined.appended_blocks;
			break;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW:
			if (data_packet_header->short_data_raw.full_message) {
				memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
				repeater->slot[ipscpacket->timeslot-1].full_message_block_count = data_packet_header->short_data_raw.appended_blocks;
			}
			repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = data_packet_header->short_data_raw.appended_blocks;
			break;
		case DMRPACKET_DATA_HEADER_DPF_PROPRIETARY_DATA:
			memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
			repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = 0;
			break;
		default:
			memset(repeater->slot[ipscpacket->timeslot-1].data_blocks, 0, sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks));
			repeater->slot[ipscpacket->timeslot-1].data_blocks_expected = 0;
			return;
	}

	console_log(LOGLEVEL_DMR "  expecting %u blocks, full message has %u blocks\n", repeater->slot[ipscpacket->timeslot-1].data_blocks_expected,
		repeater->slot[ipscpacket->timeslot-1].full_message_block_count);

	memcpy(&repeater->slot[ipscpacket->timeslot-1].data_packet_header, data_packet_header, sizeof(dmrpacket_data_header_t));
	repeater->slot[ipscpacket->timeslot-1].data_packet_header_valid = 1;
	dmr_handle_data_call_start(repeater, ipscpacket);
}

static void dmr_handle_data_selective_ack(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, dmrpacket_data_fragment_t *data_fragment) {
	uint16_t i;
	flag_t bits[8];
	uint8_t j;
	flag_t *selective_blocks;
	uint16_t selective_blocks_size;
	smstxbuf_t *smstxbuf_first_entry;

	if (repeater == NULL || data_fragment == NULL)
		return;

	smstxbuf_first_entry = smstxbuf_get_first_entry();
	if (smstxbuf_first_entry == NULL) {
		console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  sms tx buffer is empty, ignoring selective ack\n");
		return;
	}

	// Responding only if we are the sender of the message.
	if (dstid != smstxbuf_first_entry->src_id || srcid != smstxbuf_first_entry->dst_id) {
		console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  selective ack is not for the message we try to send, ignoring (dst id: %u src id: %u)\n", smstxbuf_first_entry->dst_id, smstxbuf_first_entry->src_id);
		return;
	}

	if (smstxbuf_first_entry->selective_ack_tries >= SMS_SEND_MAX_SELECTIVE_ACK_TRIES) {
		console_log(LOGLEVEL_DMR "  max. possible selective ack retry count reached, ignoring further selective acks\n");
		return;
	}
	smstxbuf_first_entry->selective_ack_tries++;

	console_log(LOGLEVEL_DMR "  replying to selective ack\n");

	selective_blocks_size = data_fragment->bytes_stored-4; // Cutting out the CRC.
	selective_blocks = (flag_t *)calloc(1, selective_blocks_size);
	if (selective_blocks == NULL) {
		console_log("  error: can't allocate memory for selective reply blocks\n");
		return;
	}

	// See the bottom of DMR AI spec. page 85. for the format.
	for (i = 0; i < selective_blocks_size; i++) {
		base_bytetobits(data_fragment->bytes[i], bits);
		for (j = 7; j > 0; j--) {
			if (bits[j] == 0) {
				console_log(LOGLEVEL_DMRDATA "  adding data block %u to selective reply\n", i*8+(7-j));
				selective_blocks[i*8+(7-j)] = 1;
			}
		}
	}
	switch (repeater->slot[ts].data_packet_header.common.service_access_point) {
		case DMRPACKET_DATA_HEADER_SAP_SHORT_DATA:
			repeaters_send_sms(repeater, ts, calltype, srcid, dstid, selective_blocks, selective_blocks_size, smstxbuf_first_entry->msg);
			break;
		case DMRPACKET_DATA_HEADER_SAP_IP_BASED_PACKET_DATA:
			repeaters_send_motorola_tms_sms(repeater, ts, calltype, srcid, dstid, selective_blocks, selective_blocks_size, smstxbuf_first_entry->msg);
			break;
	}
	free(selective_blocks);
}

static void dmr_handle_received_complete_fragment(ipscpacket_t *ipscpacket, repeater_t *repeater, dmrpacket_data_fragment_t *data_fragment) {
	struct ip *ip_packet;
	struct udphdr *udp_packet;
	uint8_t *message_data = NULL;
	uint16_t message_data_length = 0;
	dmrpacket_data_header_dd_format_t dd_format = DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE;
	char *decoded_message = NULL;
	uint8_t i;
	uint8_t *tms_msg_payload = NULL;
	uint16_t tms_msg_length;
	uint32_t ipaddr;
	dmr_id_t dstid;
	dmr_id_t srcid;
	dmr_call_type_t calltype;
	smstxbuf_t *smstxbuf_first_entry;
	flag_t is_motorola_tms_sms_received = 0;

	if (ipscpacket == NULL || repeater == NULL || data_fragment == NULL)
		return;

	calltype = ipscpacket->call_type;
	dstid = ipscpacket->dst_id;
	srcid = ipscpacket->src_id;

	switch (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.service_access_point) {
		case DMRPACKET_DATA_HEADER_SAP_IP_BASED_PACKET_DATA:
			ip_packet = (struct ip *)data_fragment->bytes;
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  received ip based packet data\n");
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    version: %u\n", ip_packet->ip_v);
			ipaddr = ntohl(ip_packet->ip_dst.s_addr);
			dstid = (ipaddr & 0xffffff);
			if (ipaddr & (0b11100000 << 24)) {
				calltype = DMR_CALL_TYPE_GROUP;
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    dst: %s (class d network id: %u (0x%.2x) dmr id: %u)\n", comm_get_ip_str(&ip_packet->ip_dst),
					(ipaddr & 0x0f000000) >> 24, (ipaddr & 0xff000000) >> 24, dstid);
			} else {
				calltype = DMR_CALL_TYPE_PRIVATE;
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    dst: %s (class a network id: %u (0x%.2x) dmr id: %u)\n", comm_get_ip_str(&ip_packet->ip_dst),
					(ipaddr & 0x7f000000) >> 24, (ipaddr & 0xff000000) >> 24, dstid);
			}
			ipaddr = ntohl(ip_packet->ip_src.s_addr);
			srcid = (ipaddr & 0xffffff);
			if (ipaddr & (0b11100000 << 24)) {
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    src: %s (class d network id: %u (0x%.2x) dmr id: %u)\n", comm_get_ip_str(&ip_packet->ip_src),
					(ipaddr & 0x0f000000) >> 24, (ipaddr & 0xff000000) >> 24, srcid);
			} else {
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    src: %s (class a network id: %u (0x%.2x) dmr id: %u)\n", comm_get_ip_str(&ip_packet->ip_src),
					(ipaddr & 0x7f000000) >> 24, (ipaddr & 0xff000000) >> 24, srcid);
			}
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    length: %u\n", ntohs(ip_packet->ip_len));
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    header length: %u\n", ip_packet->ip_hl*4);
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    ttl: %u\n", ip_packet->ip_ttl);
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    proto: %u\n", ip_packet->ip_p);
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    checksum: 0x%.4x (", ip_packet->ip_sum);
			if (comm_calcipheaderchecksum(ip_packet) == ip_packet->ip_sum)
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "ok)\n");
			else {
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "error, dropping packet)\n");
				return;
			}

			switch (ip_packet->ip_p) {
				case IPPROTO_UDP:
					udp_packet = (struct udphdr *)(data_fragment->bytes+ip_packet->ip_hl*4);
					console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "    got udp packet\n");
					console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      dst port: %u\n", ntohs(udp_packet->dest));
					console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      src port: %u\n", ntohs(udp_packet->source));
					console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      length: %u\n", ntohs(udp_packet->len));
					console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      checksum: 0x%.4x (", ntohs(udp_packet->check));
					if (comm_calcudpchecksum(ip_packet, udp_packet) == udp_packet->check)
						console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "ok)\n");
					else {
						console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "error, dropping packet)\n");
						return;
					}

					switch (ntohs(udp_packet->dest)) {
						case 4007: // Motorola SMS UDP port.
							// The message has a 10 byte header.
							console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      motorola tms header: ");
							tms_msg_length = ntohs(udp_packet->len)-sizeof(struct udphdr);
							tms_msg_payload = (uint8_t *)(udp_packet)+sizeof(struct udphdr);
							for (i = 0; i < min(10, tms_msg_length); i += 2) {
								console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "%.2x", *(tms_msg_payload+i));
								if (i+1 < min(10, tms_msg_length))
									console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "%.2x", *(tms_msg_payload+i+1));
							}
							console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "\n");

							if (tms_msg_payload[0] == 0x00 && tms_msg_payload[1] == 0x03 && tms_msg_payload[2] == 0xbf) {
								console_log(LOGLEVEL_DMR "      got a motorola tms ack\n");

								// If the Motorola TMS ACK is for us, we reply with a standard ACK.
								if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested &&
									srcid != DMRSHARK_DEFAULT_DMR_ID && dstid == DMRSHARK_DEFAULT_DMR_ID && calltype == DMR_CALL_TYPE_PRIVATE) {
										repeaters_send_ack(repeater, srcid, dstid, ipscpacket->timeslot-1, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.service_access_point);
										return;
								}

								smstxbuf_first_entry = smstxbuf_get_first_entry();
								if (smstxbuf_first_entry != NULL) {
									if (!smstxbuf_first_entry->motorola_tms_sms) {
										console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      sms tx buffer entry is not a motorola tms sms\n");
										return;
									}

									if (smstxbuf_first_entry->dst_id == srcid &&
										smstxbuf_first_entry->src_id == dstid &&
										smstxbuf_first_entry->call_type == calltype) {
										 	console_log(LOGLEVEL_DMR "      got ack for sms tx buffer entry:\n");
										 	smstxbuf_print_entry(smstxbuf_first_entry);
										 	smstxbuf_remove_first_entry();
									} else
										console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      ack is not for us (dst id: %u src id: %u)\n", smstxbuf_first_entry->dst_id, smstxbuf_first_entry->src_id);
								} else
									console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "      ack is not for us, sms tx buffer is empty\n");

								return;
							}

							if (tms_msg_length > 10) {
								message_data = (uint8_t *)(udp_packet)+sizeof(struct udphdr)+10;
								message_data_length = ntohs(udp_packet->len)-sizeof(struct udphdr)-10;
								is_motorola_tms_sms_received = 1;
							} else
								console_log(LOGLEVEL_DMR "      motorola tms message doesn't have a payload to decode\n");
							break;
						default:
							console_log(LOGLEVEL_DMR "    unhandled udp dst port %u\n", ntohs(udp_packet->dest));
					}
					break;
				default:
					console_log(LOGLEVEL_DMR "    unhandled ip proto %u\n", ip_packet->ip_p);
					return;
			}
			break;
		case DMRPACKET_DATA_HEADER_SAP_SHORT_DATA:
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  received short data\n");
			message_data = data_fragment->bytes+2; // Hytera has a 2 byte pre-padding.
			message_data_length = data_fragment->bytes_stored-2-4; // -4 - leaving out the fragment CRC.
			dd_format = repeater->slot[ipscpacket->timeslot-1].data_packet_header.short_data_defined.dd_format;
			break;
		default:
			console_log(LOGLEVEL_DMR "  unhandled service access point: %s\n", dmrpacket_data_header_get_readable_sap(repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.service_access_point));
			return;
	}

	decoded_message = dmrpacket_data_convertmsg(message_data, message_data_length, NULL, dd_format, DMRPACKET_DATA_HEADER_DD_FORMAT_UTF8, 0);
	if (decoded_message == NULL)
		console_log(LOGLEVEL_DMR "  message decoding failed\n");
	else {
		if (!isprint(decoded_message[0]))
			console_log(LOGLEVEL_DMR "  message is not printable\n");
		else {
			console_log(LOGLEVEL_DMR "  decoded message: %s\n", decoded_message); // TODO: upload decoded message to remotedb

			// Message is OK, and for us?
			if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested &&
				srcid != DMRSHARK_DEFAULT_DMR_ID && dstid == DMRSHARK_DEFAULT_DMR_ID && calltype == DMR_CALL_TYPE_PRIVATE) {
					repeaters_send_ack(repeater, srcid, dstid, ipscpacket->timeslot-1, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.service_access_point);
					if (is_motorola_tms_sms_received && tms_msg_payload != NULL)
						repeaters_send_motorola_tms_ack(repeater, ipscpacket->timeslot-1, calltype, srcid, dstid, NULL, 0, tms_msg_payload[4] & 0b11111);
			}
		}
	}
}

static void dmr_handle_data_fragment_assembly(ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_fragment_t *data_fragment = NULL;
	uint8_t i;
	flag_t *selective_blocks;
	flag_t erroneous_block_found = 0;

	// Checking if there were erroneous blocks.
	selective_blocks = (flag_t *)calloc(1, repeater->slot[ipscpacket->timeslot-1].full_message_block_count);
	if (selective_blocks == NULL) {
		console_log("  error: can't allocate memory for selective blocks\n");
		return;
	}
	for (i = 0; i < repeater->slot[ipscpacket->timeslot-1].full_message_block_count; i++) {
		if (!repeater->slot[ipscpacket->timeslot-1].data_blocks[i].received_ok) {
			selective_blocks[i] = 1;
			erroneous_block_found = 1;
		}
	}
	if (erroneous_block_found) {
		if (repeater->slot[ipscpacket->timeslot-1].selective_ack_requests_sent >= SMS_SEND_MAX_SELECTIVE_ACK_TRIES) {
			console_log(LOGLEVEL_DMR "  found erroneous blocks, but max. selective ack requests count (%u) reached\n", SMS_SEND_MAX_SELECTIVE_ACK_TRIES);
			return;
		}
		if (ipscpacket->src_id == DMRSHARK_DEFAULT_DMR_ID)
			console_log(LOGLEVEL_DMR "  found erroneous blocks originating from us!\n");
		else {
			repeaters_send_selective_ack(repeater, ipscpacket->src_id, ipscpacket->dst_id, ipscpacket->timeslot-1, selective_blocks, repeater->slot[ipscpacket->timeslot-1].full_message_block_count,
				repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.service_access_point);
			repeater->slot[ipscpacket->timeslot-1].selective_ack_requests_sent++;
		}
		free(selective_blocks);
		return;
	}
	free(selective_blocks);

	// Now we have every block with correct CRC. Trying to extract the fragment.
	data_fragment = dmrpacket_data_extract_fragment_from_blocks(repeater->slot[ipscpacket->timeslot-1].data_blocks,
		repeater->slot[ipscpacket->timeslot-1].full_message_block_count);

	if (data_fragment != NULL && data_fragment->bytes_stored > 0) {
		// Response with data blocks? That must be a selective ACK.
		if (repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_RESPONSE &&
			dmrpacket_data_header_decode_response(&repeater->slot[ipscpacket->timeslot-1].data_packet_header) == DMRPACKET_DATA_HEADER_RESPONSETYPE_SELECTIVE_ACK) {
				dmr_handle_data_selective_ack(repeater, ipscpacket->timeslot-1, ipscpacket->call_type, ipscpacket->dst_id, ipscpacket->src_id, data_fragment);
				return;
		}

		dmr_handle_received_complete_fragment(ipscpacket, repeater, data_fragment);

		// If we are not waiting for an ack, then the data session ended.
		if (!repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested)
			dmr_handle_data_call_end(repeater, ipscpacket->timeslot-1);
	}
}

static void dmr_handle_data_received_block(ipscpacket_t *ipscpacket, repeater_t *repeater, dmrpacket_data_block_t *data_block) {
	if (ipscpacket == NULL || repeater == NULL)
		return;

	if (data_block != NULL) {
		if (ipscpacket->src_id != DMRSHARK_DEFAULT_DMR_ID && repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested) {
			// Only confirmed data blocks have serial numbers stored in them.
			if (data_block->serialnr < sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks)/sizeof(repeater->slot[ipscpacket->timeslot-1].data_blocks[0])) {
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  storing block with serial nr. #%u\n", data_block->serialnr);
				memcpy(&repeater->slot[ipscpacket->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
			} else
				console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  not storing block #%u, serial nr. is out of bounds\n", data_block->serialnr);
		} else {
			console_log(LOGLEVEL_DMR LOGLEVEL_DEBUG "  storing block #%u\n", repeater->slot[ipscpacket->timeslot-1].data_blocks_received);
			memcpy(&repeater->slot[ipscpacket->timeslot-1].data_blocks[repeater->slot[ipscpacket->timeslot-1].data_blocks_received], data_block, sizeof(dmrpacket_data_block_t));
		}
	} else
		memset(&repeater->slot[ipscpacket->timeslot-1].data_blocks[repeater->slot[ipscpacket->timeslot-1].data_blocks_received], 0, sizeof(dmrpacket_data_block_t));

	repeater->slot[ipscpacket->timeslot-1].data_blocks_received++;

	// Got all expected blocks?
	if (repeater->slot[ipscpacket->timeslot-1].data_blocks_expected == repeater->slot[ipscpacket->timeslot-1].data_blocks_received) {
		console_log(LOGLEVEL_DMR "  got all %u expected blocks\n", repeater->slot[ipscpacket->timeslot-1].data_blocks_expected);
		dmr_handle_data_fragment_assembly(ipscpacket, repeater);
	}
}

void dmr_handle_data_34rate(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	trellis_dibits_t *packet_payload_dibits = NULL;
	trellis_constellationpoints_t *packet_payload_constellationpoints = NULL;
	trellis_tribits_t *packet_payload_tribits = NULL;
	dmrpacket_data_binary_t *data_binary = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL ||
		repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_DATA_CALL_RUNNING ||
		!repeater->slot[ipscpacket->timeslot-1].data_packet_header_valid)
			return;

	console_log(LOGLEVEL_DMR "dmr data [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: got 3/4 rate block #%u/%u, ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst),
		repeater->slot[ipscpacket->timeslot-1].data_blocks_received+1, repeater->slot[ipscpacket->timeslot-1].data_blocks_expected);

	console_log(LOGLEVEL_DMR "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_extract_bits(&ipscpacket->payload_bits))));
	dmrpacket_slot_type_decode(dmrpacket_slot_type_extract_bits(&ipscpacket->payload_bits));

	packet_payload_info_bits = dmrpacket_extract_info_bits(&ipscpacket->payload_bits);
	packet_payload_dibits = trellis_extract_dibits(packet_payload_info_bits);
	packet_payload_dibits = trellis_deinterleave_dibits(packet_payload_dibits);
	packet_payload_constellationpoints = trellis_getconstellationpoints(packet_payload_dibits);
	packet_payload_tribits = trellis_extract_tribits(packet_payload_constellationpoints);
	data_binary = trellis_extract_binary(packet_payload_tribits);
	data_block_bytes = dmrpacket_data_convert_binary_to_block_bytes(data_binary);
	data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_34_DATA, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested);

	dmr_handle_data_received_block(ipscpacket, repeater, data_block);
}

void dmr_handle_data_12rate(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater) {
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (ip_packet == NULL || ipscpacket == NULL || repeater == NULL ||
		repeater->slot[ipscpacket->timeslot-1].state != REPEATER_SLOT_STATE_DATA_CALL_RUNNING ||
		!repeater->slot[ipscpacket->timeslot-1].data_packet_header_valid)
			return;

	console_log(LOGLEVEL_DMR "dmr data [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_DMR "->%s]: got 1/2 rate block #%u/%u, ", repeaters_get_display_string_for_ip(&ip_packet->ip_dst),
		repeater->slot[ipscpacket->timeslot-1].data_blocks_received+1, repeater->slot[ipscpacket->timeslot-1].data_blocks_expected);

	console_log(LOGLEVEL_DMR "sync pattern: %s\n", dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_extract_bits(&ipscpacket->payload_bits))));
	dmrpacket_slot_type_decode(dmrpacket_slot_type_extract_bits(&ipscpacket->payload_bits));

	data_block_bytes = dmrpacket_data_convert_payload_bptc_data_bits_to_block_bytes(dmrpacket_data_extract_and_repair_bptc_data(&ipscpacket->payload_bits));
	data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_12_DATA, repeater->slot[ipscpacket->timeslot-1].data_packet_header.common.response_requested);

	dmr_handle_data_received_block(ipscpacket, repeater, data_block);
}
