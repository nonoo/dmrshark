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

#include "dmr-data.h"
#include "data-packet-txbuf.h"
#include "smstxbuf.h"

#include <libs/daemon/console.h>
#include <libs/comm/repeaters.h>

#include <string.h>
#include <math.h>
#include <stdlib.h>

static uint8_t dmr_data_motorola_tms_tx_seqnum = 0;

void dmr_data_send_ack(repeater_t *repeater, dmr_id_t dstid, dmr_id_t srcid, dmr_timeslot_t ts, dmrpacket_data_header_sap_t sap) {
	dmrpacket_data_header_t data_header;
	ipscpacket_payload_t *ipscpacket_payload;

	if (repeater == NULL)
		return;

	console_log(LOGLEVEL_DMRDATA "dmr data: sending ack to %u on repeater %s ts%u, status %u\n", dstid, repeaters_get_display_string_for_ip(&repeater->ipaddr), ts+1, repeater->slot[ts].rx_seqnum);

	memset(&data_header, 0, sizeof(dmrpacket_data_header_t));
	data_header.common.dst_is_a_group = 0;
	data_header.common.response_requested = 0;
	data_header.common.dst_llid = dstid;
	data_header.common.src_llid = srcid;
	data_header.common.data_packet_format = DMRPACKET_DATA_HEADER_DPF_RESPONSE;
	data_header.common.service_access_point = sap;

	data_header.response.blocks_to_follow = 0;
	data_header.response.class = 0;
	data_header.response.type = 1;
	data_header.response.status = repeater->slot[ts].rx_seqnum;
	data_header.response.responsetype = DMRPACKET_DATA_HEADER_RESPONSETYPE_ACK;

	ipscpacket_payload = ipscpacket_construct_payload_data_header(&data_header);
	repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_DATA_HEADER, DMR_CALL_TYPE_PRIVATE, dstid, srcid, ipscpacket_payload)));
}

// Selective blocks is a flag array which has 1 set where the corresponding block is erroneous.
void dmr_data_send_selective_ack(repeater_t *repeater, dmr_id_t dstid, dmr_id_t srcid, dmr_timeslot_t ts,
	flag_t *selective_blocks, uint8_t selective_blocks_size, dmrpacket_data_header_sap_t service_access_point) {

	uint8_t i;
	dmrpacket_data_packet_t data_packet;
	uint8_t *payload;
	uint16_t payload_size;
	uint8_t data_blocks_needed;

	if (repeater == NULL || selective_blocks == NULL || selective_blocks_size == 0)
		return;

	console_log(LOGLEVEL_DMRDATA "dmr data: sending selective ack to %u on repeater %s ts%u, blocks: ", dstid, repeaters_get_display_string_for_ip(&repeater->ipaddr), ts+1);

	payload_size = ceil(selective_blocks_size/8.0);
	dmrpacket_data_get_needed_blocks_count(payload_size, DMRPACKET_DATA_TYPE_RATE_12_DATA, 0, &data_blocks_needed);
	payload_size = data_blocks_needed*dmrpacket_data_get_block_size(DMRPACKET_DATA_TYPE_RATE_12_DATA, 0)-4;
	payload = (uint8_t *)malloc(payload_size);
	if (payload == NULL) {
		console_log("dmr data error: can't allocate memory for selective ack payload\n");
		return;
	}
	memset(payload, 0xff, payload_size);
	for (i = 0; i < selective_blocks_size; i++) {
		if (selective_blocks[i]) {
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%u ", i);

			payload[i/8] &= ~(1 << (i % 8));
		}
	}
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");

	dmrpacket_data_construct_fragment(payload, payload_size, DMRPACKET_DATA_TYPE_RATE_12_DATA, 0, &data_packet.fragment);
	free(payload);

	memset(&data_packet.header, 0, sizeof(dmrpacket_data_header_t));
	data_packet.header.common.dst_is_a_group = 0;
	data_packet.header.common.response_requested = 0;
	data_packet.header.common.dst_llid = dstid;
	data_packet.header.common.src_llid = srcid;
	data_packet.header.common.data_packet_format = DMRPACKET_DATA_HEADER_DPF_RESPONSE;
	data_packet.header.common.service_access_point = service_access_point;

	// data_packet.header.response.blocks_to_follow will be filled by repeaters_send_data_packet()
	data_packet.header.response.class = 2;
	data_packet.header.response.type = 0;
	data_packet.header.response.status = repeater->slot[ts].rx_seqnum;
	data_packet.header.response.responsetype = DMRPACKET_DATA_HEADER_RESPONSETYPE_SELECTIVE_ACK;

	data_packet.number_of_csbk_preambles_to_send = 0;
	data_packet.data_type = DMRPACKET_DATA_TYPE_RATE_12_DATA;

	repeaters_send_data_packet(repeater, ts, NULL, 0, &data_packet);
}

static void dmr_data_send_ip_packet(flag_t broadcast_to_all_repeaters, uint8_t number_of_csbk_preambles_to_send, repeater_t *repeater, dmr_timeslot_t ts,
	dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, struct iphdr *ip_packet) {

	dmrpacket_data_packet_t data_packet;
	flag_t confirmed = (calltype == DMR_CALL_TYPE_PRIVATE ? 1 : 0);

	if ((!broadcast_to_all_repeaters && repeater == NULL) || ip_packet == NULL)
		return;

	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "dmr data: sending %s ip packet to %u on ts%u\n", dmr_get_readable_call_type(calltype), dstid, ts+1);

	data_packet.data_type = (calltype == DMR_CALL_TYPE_PRIVATE ? DMRPACKET_DATA_TYPE_RATE_34_DATA : DMRPACKET_DATA_TYPE_RATE_12_DATA);
	dmrpacket_data_construct_fragment((uint8_t *)ip_packet, ntohs(ip_packet->tot_len), data_packet.data_type, confirmed, &data_packet.fragment);

	// Constructing the data header.
	data_packet.header.common.dst_is_a_group = (calltype == DMR_CALL_TYPE_GROUP);
	data_packet.header.common.response_requested = confirmed;
	data_packet.header.common.dst_llid = dstid;
	data_packet.header.common.src_llid = srcid;
	data_packet.header.common.data_packet_format = DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA;
	data_packet.header.common.service_access_point = DMRPACKET_DATA_HEADER_SAP_IP_BASED_PACKET_DATA;

	// data_packet.header.confirmed_data.pad_octet_count will be filled by repeaters_send_data_packet()
	// data_packet.header.confirmed_data.blocks_to_follow will be filled by repeaters_send_data_packet()
	// data_packet.header.confirmed_data.full_message will be filled by repeaters_send_data_packet()
	data_packet.header.confirmed_data.fragmentseqnum = 0b1000; // Indicating last fragment (see DMR AI spec. page 74.)
	data_packet.header.confirmed_data.resync = 0;
	data_packet.header.confirmed_data.sendseqnum = dmr_data_motorola_tms_tx_seqnum % 8;

	data_packet.number_of_csbk_preambles_to_send = number_of_csbk_preambles_to_send;

	data_packet_txbuf_add(broadcast_to_all_repeaters, repeater, ts, &data_packet);
}

void dmr_data_send_motorola_tms_sms(flag_t broadcast_to_all_repeaters, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, char *msg) {
	struct iphdr *ip_packet;

	if ((!broadcast_to_all_repeaters && repeater == NULL) || msg == NULL)
		return;

	console_log(LOGLEVEL_DMRDATA "dmr data: sending %s motorola sms to %u on ts%u: %s\n", dmr_get_readable_call_type(calltype), dstid, ts+1, msg);

	dmr_data_motorola_tms_tx_seqnum++;
	ip_packet = dmrpacket_data_construct_payload_motorola_sms(msg, dstid, srcid, calltype, dmr_data_motorola_tms_tx_seqnum);
	dmr_data_send_ip_packet(broadcast_to_all_repeaters, 1, repeater, ts, calltype, dstid, srcid, ip_packet);
	free(ip_packet);
}

void dmr_data_send_motorola_tms_ack(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, uint8_t rx_seqnum) {
	struct iphdr *ip_packet;

	if (repeater == NULL)
		return;

	console_log(LOGLEVEL_DMRDATA "dmr data: sending %s motorola tms ack to %u on ts%u for rx seqnum 0x%.2x\n", dmr_get_readable_call_type(calltype), dstid, ts+1, rx_seqnum);

	dmr_data_motorola_tms_tx_seqnum++;
	ip_packet = dmrpacket_data_construct_payload_motorola_tms_ack(dstid, srcid, calltype, rx_seqnum);
	dmr_data_send_ip_packet(0, 1, repeater, ts, calltype, dstid, srcid, ip_packet);
	free(ip_packet);
}

void dmr_data_send_sms(flag_t broadcast_to_all_repeaters, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, char *msg) {
	dmrpacket_data_packet_t data_packet;
	char *utf16le_msg;
	uint16_t utf16le_msg_length;
	flag_t confirmed = (calltype == DMR_CALL_TYPE_PRIVATE ? 1 : 0);

	if ((!broadcast_to_all_repeaters && repeater == NULL) || msg == NULL)
		return;

	console_log(LOGLEVEL_DMRDATA "dmr-data: sending %s sms to %u on ts%u: %s\n", dmr_get_readable_call_type(calltype), dstid, ts+1, msg);

	// We are using a 2 byte left padding because Hytera devices seem to add it to every message they send, and cut it from every message they receive.
	utf16le_msg = dmrpacket_data_convertmsg((uint8_t *)msg, strlen(msg), &utf16le_msg_length, DMRPACKET_DATA_HEADER_DD_FORMAT_UTF8, DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE, 2);
	data_packet.data_type = (calltype == DMR_CALL_TYPE_PRIVATE ? DMRPACKET_DATA_TYPE_RATE_34_DATA : DMRPACKET_DATA_TYPE_RATE_12_DATA);
	dmrpacket_data_construct_fragment((uint8_t *)utf16le_msg, utf16le_msg_length, data_packet.data_type, confirmed, &data_packet.fragment);
	free(utf16le_msg);

	// Constructing the data header.
	data_packet.header.common.dst_is_a_group = (calltype == DMR_CALL_TYPE_GROUP);
	data_packet.header.common.response_requested = confirmed;
	data_packet.header.common.dst_llid = dstid;
	data_packet.header.common.src_llid = srcid;
	data_packet.header.common.data_packet_format = DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED;
	data_packet.header.common.service_access_point = DMRPACKET_DATA_HEADER_SAP_SHORT_DATA;

	// data_header.short_data_defined.appended_blocks will be filled by repeaters_send_data_packet()
	data_packet.header.short_data_defined.dd_format = DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE;
	data_packet.header.short_data_defined.resync = 1;
	// data_packet.header.short_data_defined.full_message will be filled by repeaters_send_data_packet()
	data_packet.header.short_data_defined.bit_padding = (dmrpacket_data_get_block_size(data_packet.data_type, confirmed)*data_packet.fragment.data_blocks_needed-data_packet.fragment.bytes_stored-4)*8;
	data_packet.number_of_csbk_preambles_to_send = 1;

	data_packet_txbuf_add(broadcast_to_all_repeaters, repeater, ts, &data_packet);
}

void dmr_data_send_sms_rms_volume_if_needed(repeater_t *repeater, dmr_timeslot_t ts) {
	char msg[100];
	int8_t avg_rms_vol = VOICESTREAMS_INVALID_RMS_VALUE;

	// No RMS volume SMS for echo service replies.
	if (repeater->slot[ts].src_id == DMRSHARK_DEFAULT_DMR_ID || repeater->slot[ts].src_id == 9990)
		return;

	// Only sending RMS volume after echo service requests.
	if (repeater->slot[ts].dst_id != DMRSHARK_DEFAULT_DMR_ID && repeater->slot[ts].dst_id != 9990)
		return;

	// DMRPlus echo service is only active on TS2.
	if (repeater->slot[ts].dst_id == 9990 && ts != 1)
		return;

	if (repeater->slot[ts].voicestream != NULL)
		avg_rms_vol = repeater->slot[ts].voicestream->avg_rms_vol;

	if (repeater->slot[ts].avg_rssi != 0 && avg_rms_vol != VOICESTREAMS_INVALID_RMS_VALUE)
		snprintf(msg, sizeof(msg), "Avg. RMS vol.: %ddB, avg. RSSI %ddB * dmrshark by HA2NON", avg_rms_vol, repeater->slot[ts].avg_rssi);
	else if (repeater->slot[ts].avg_rssi != 0 && avg_rms_vol == VOICESTREAMS_INVALID_RMS_VALUE)
		snprintf(msg, sizeof(msg), "Avg. RSSI %ddB * dmrshark by HA2NON", repeater->slot[ts].avg_rssi);
	else if (repeater->slot[ts].avg_rssi == 0 && avg_rms_vol != VOICESTREAMS_INVALID_RMS_VALUE)
		snprintf(msg, sizeof(msg), "Avg. RMS vol.: %ddB * dmrshark by HA2NON", avg_rms_vol);
	else
		return;

	smstxbuf_add(repeater, ts, DMR_CALL_TYPE_PRIVATE, repeater->slot[ts].src_id, DMR_DATA_TYPE_NORMAL_SMS, msg, 0);
	smstxbuf_add(repeater, ts, DMR_CALL_TYPE_PRIVATE, repeater->slot[ts].src_id, DMR_DATA_TYPE_MOTOROLA_TMS_SMS, msg, 0);
}
