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
#include <libs/base/base.h>

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
	remotedb_update_stats_callend(repeater, ipscpacket->timeslot);
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
	remotedb_update_stats_callend(repeater, ts+1);
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
