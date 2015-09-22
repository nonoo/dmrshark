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

#include <libs/base/base.h>
#include <libs/daemon/console.h>
#include <libs/base/dmr.h>
#include <libs/coding/crc.h>
#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/dmrpacket/dmrpacket-lc.h>
#include <libs/dmrpacket/dmrpacket-sync.h>
#include <libs/dmrpacket/dmrpacket-slot-type.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#define IPSC_PACKET_SIZE1 72
#define IPSC_PACKET_SIZE2 103

char *ipscpacket_get_readable_slot_type(ipscpacket_slot_type_t slot_type) {
	switch (slot_type) {
		case IPSCPACKET_SLOT_TYPE_VOICE_LC_HEADER: return "voice lc header";
		case IPSCPACKET_SLOT_TYPE_TERMINATOR_WITH_LC: return "terminator with lc";
		case IPSCPACKET_SLOT_TYPE_CSBK: return "csbk"; // Control Signaling Block
		case IPSCPACKET_SLOT_TYPE_DATA_HEADER: return "data header";
		case IPSCPACKET_SLOT_TYPE_1_2_RATE_DATA: return "1/2 rate data";
		case IPSCPACKET_SLOT_TYPE_3_4_RATE_DATA: return "3/4 rate data";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A: return "voice data a";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B: return "voice data b";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C: return "voice data c";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D: return "voice data d";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E: return "voice data e";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_F: return "voice data f";
		default: return "unknown";
	}
}

// Swaps given payload bytes and then converts them to an uint8_t array of bits.
static dmrpacket_payload_bits_t *ipscpacket_convertpayloadtobits(ipscpacket_payload_t *payload) {
	static dmrpacket_payload_bits_t payload_bits;
	ipscpacket_payload_t swapped_bytes = { .bytes = { 0, } };
	uint8_t i;

	if (payload == NULL)
		return NULL;

	// Swapping the bytes.
	for (i = 0; i < IPSCPACKET_PAYLOAD_SIZE-1; i += 2) {
		swapped_bytes.bytes[i] = payload->bytes[i+1];
		swapped_bytes.bytes[i+1] = payload->bytes[i];
	}

	base_bytestobits(swapped_bytes.bytes, IPSCPACKET_PAYLOAD_SIZE-1, payload_bits.bits, sizeof(payload_bits.bits));

	return &payload_bits;
}

// Decodes the UDP packet given in udp_packet to ipsc_packet,
// returns 1 if decoding was successful, otherwise returns 0.
flag_t ipscpacket_decode(struct udphdr *udppacket, ipscpacket_t *ipscpacket, flag_t packet_from_us) {
	ipscpacket_raw_t *ipscpacket_raw = (ipscpacket_raw_t *)((uint8_t *)udppacket + sizeof(struct udphdr));
	int ipscpacket_raw_length = 0;
	int i;
	loglevel_t loglevel;

	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	ipscpacket_raw_length = ntohs(udppacket->len)-sizeof(struct udphdr);
	if (ipscpacket_raw_length != IPSC_PACKET_SIZE1 && ipscpacket_raw_length != IPSC_PACKET_SIZE2) {
		//console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, packet size is %u not %u or %u bytes.\n",
		//	ipscpacket_raw_length, IPSC_PACKET_SIZE1, IPSC_PACKET_SIZE2);
		return 0;
	}

	loglevel = console_get_loglevel();
	if (loglevel.flags.debug && loglevel.flags.ipsc) {
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decoding: ");
		for (i = 0; i < ipscpacket_raw_length; i++)
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "%.2x ", *((uint8_t *)ipscpacket_raw+i));
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "\n");
	}

	if (!packet_from_us && ipscpacket_raw->udp_source_port != udppacket->source) {
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, UDP source port (%u) is not equal to port in IPSC packet (%u)\n",
			ipscpacket_raw->udp_source_port, udppacket->source);
		return 0;
	}

	if (ipscpacket_raw->delimiter != 0x1111) {
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, delimiter mismatch (it's %.4x, should be 0x1111)\n",
			ipscpacket_raw->delimiter);
		return 0;
	}

	if (ipscpacket_raw->timeslot_raw == 0x1111)
		ipscpacket->timeslot = 1;
	else if (ipscpacket_raw->timeslot_raw == 0x2222)
		ipscpacket->timeslot = 2;
	else {
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, invalid timeslot (%.4x)\n", ipscpacket_raw->timeslot_raw);
		return 0;
	}

	if (ipscpacket_raw->calltype != DMR_CALL_TYPE_PRIVATE &&
		ipscpacket_raw->calltype != DMR_CALL_TYPE_GROUP) {
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, invalid call type (%.2x)\n", ipscpacket_raw->calltype);
			return 0;
	}

	ipscpacket->slot_type = ipscpacket_raw->slot_type;
	ipscpacket->call_type = ipscpacket_raw->calltype;
	ipscpacket->dst_id = ipscpacket_raw->dst_id_raw3 << 16 | ipscpacket_raw->dst_id_raw2 << 8 | ipscpacket_raw->dst_id_raw1;
	ipscpacket->src_id = ipscpacket_raw->src_id_raw3 << 16 | ipscpacket_raw->src_id_raw2 << 8 | ipscpacket_raw->src_id_raw1;
	memcpy(ipscpacket->payload.bytes, ipscpacket_raw->payload.bytes, IPSCPACKET_PAYLOAD_SIZE);
	memcpy(&ipscpacket->payload_bits, ipscpacket_convertpayloadtobits(&ipscpacket->payload), sizeof(dmrpacket_payload_bits_t));

	return 1;
}

flag_t ipscpacket_heartbeat_decode(struct udphdr *udppacket) {
	uint8_t heartbeat[] = { 0x00, 0x00, 0x00, 0x14 };

	if (udppacket == NULL)
		return 0;

	if (memcmp((uint8_t *)udppacket + sizeof(struct udphdr) + 5, heartbeat, sizeof(heartbeat)) == 0)
		return 1;
	return 0;
}

ipscpacket_raw_t *ipscpacket_construct(uint8_t seqnum, dmr_timeslot_t ts, ipscpacket_slot_type_t slot_type,
	dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, ipscpacket_payload_t *payload) {

	static ipscpacket_raw_t ipscpacket_raw;

	if (ts < 0 || ts > 1 || calltype < 0 || calltype > 1 || payload == NULL)
		return NULL;

//TODO
//00 00
//00 00
//00
//00 00 00
//01
//00 05 01 02 00 00 00
//22 22
//11 11
//11 11
//00 00 ft
//10 00 r4
// sync bytes: 25 51 27 d0 05 f7
//5d 18 10 98 05 05 9e d9 e8 ef c7 b8 a2 16 12 55 00 7d 76 5f 81 38 e3 29 98 ca 54 e5 5a 20 09 c0 00 e3
//02 00
//01
//00
//09 00 00 00 a2 12 00 00

	memset(&ipscpacket_raw, 0, sizeof(ipscpacket_raw_t));

	ipscpacket_raw.seq = seqnum;
	ipscpacket_raw.packet_type = 0x01;
	ipscpacket_raw.reserved3[1] = 0x05;
	ipscpacket_raw.reserved3[2] = 0x01;
	ipscpacket_raw.reserved3[3] = 0x02;
	ipscpacket_raw.timeslot_raw = (ts == 0 ? 0x1111 : 0x2222);
	ipscpacket_raw.slot_type = slot_type;
	ipscpacket_raw.delimiter = 0x1111;
	ipscpacket_raw.reserved4[0] = 0x10;
	memcpy(&ipscpacket_raw.payload, payload, sizeof(ipscpacket_payload_t));
	ipscpacket_raw.reserved5[0] = 0x02;
	ipscpacket_raw.calltype = calltype;
	ipscpacket_raw.dst_id_raw1 = (dstid & 0xff);
	ipscpacket_raw.dst_id_raw2 = ((dstid >> 8) & 0xff);
	ipscpacket_raw.dst_id_raw3 = ((dstid >> 16) & 0xff);
	ipscpacket_raw.src_id_raw1 = (srcid & 0xff);
	ipscpacket_raw.src_id_raw2 = ((srcid >> 8) & 0xff);
	ipscpacket_raw.src_id_raw3 = ((srcid >> 16) & 0xff);

	return &ipscpacket_raw;
}

ipscpacket_payload_t *ipscpacket_construct_payload_voice_lc_header(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_info_bits_t *payload_info_bits;
	dmrpacket_payload_bits_t payload_bits;

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));

	payload_info_bits = dmrpacket_data_bptc_interleave(bptc_196_96_generate(dmrpacket_lc_construct_voice_lc_header(call_type, dst_id, src_id)));
	dmrpacket_insert_info_bits(&payload_bits, payload_info_bits);
	dmrpacket_slot_type_insert_bits(&payload_bits, dmrpacket_slot_type_construct_bits(1, DMRPACKET_DATA_TYPE_VOICE_LC_HEADER));
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE)); // TODO: ?
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_terminator_with_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_info_bits_t *payload_info_bits;
	dmrpacket_payload_bits_t payload_bits;

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));

	payload_info_bits = dmrpacket_data_bptc_interleave(bptc_196_96_generate(dmrpacket_lc_construct_terminator_with_lc(call_type, dst_id, src_id)));
	dmrpacket_insert_info_bits(&payload_bits, payload_info_bits);
	dmrpacket_slot_type_insert_bits(&payload_bits, dmrpacket_slot_type_construct_bits(1, DMRPACKET_DATA_TYPE_TERMINATOR_WITH_LC));
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE)); // TODO: ?
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_voice_frame(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id,
	ipscpacket_slot_type_t slot_type, dmrpacket_payload_voice_bits_t *voice_bits, vbptc_16_11_t *emb_signalling_lc_vbptc_bits) {

	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_bits_t payload_bits;
	dmrpacket_emb_signalling_lc_fragment_bits_t emb_signalling_lc_fragment_bits = { .bits = { 0, } };

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));

	dmrpacket_insert_voice_bits(&payload_bits, voice_bits);

	switch (slot_type) {
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A:
			dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE));
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_FIRST_FRAGMENT));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, 0, emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_CONTINUATION));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t), emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_CONTINUATION));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t)*2, emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_LAST_FRAGMENT));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t)*3, emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_F:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits); // Note that this is a null fragment.
			break;
	}

	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}
