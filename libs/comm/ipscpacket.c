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

#include "ipscpacket.h"
#include "repeaters.h"

#include <libs/base/base.h>
#include <libs/base/log.h>
#include <libs/daemon/console.h>
#include <libs/base/dmr.h>
#include <libs/coding/crc.h>
#include <libs/coding/trellis.h>
#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/dmrpacket/dmrpacket-lc.h>
#include <libs/dmrpacket/dmrpacket-sync.h>
#include <libs/dmrpacket/dmrpacket-slot-type.h>
#include <libs/comm/comm.h>
#include <libs/config/config.h>

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
		case IPSCPACKET_SLOT_TYPE_RATE_12_DATA: return "rate 1/2 data";
		case IPSCPACKET_SLOT_TYPE_RATE_34_DATA: return "rate 3/4 data";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A: return "voice data a";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B: return "voice data b";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C: return "voice data c";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D: return "voice data d";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E: return "voice data e";
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_F: return "voice data f";
		case IPSCPACKET_SLOT_TYPE_IPSC_SYNC: return "ipsc sync";
		default: return "unknown";
	}
}

ipscpacket_slot_type_t ipscpacket_get_slot_type_for_data_type(dmrpacket_data_type_t data_type) {
	switch (data_type) {
		case DMRPACKET_DATA_TYPE_VOICE_LC_HEADER: return IPSCPACKET_SLOT_TYPE_VOICE_LC_HEADER;
		case DMRPACKET_DATA_TYPE_TERMINATOR_WITH_LC: return IPSCPACKET_SLOT_TYPE_TERMINATOR_WITH_LC;
		case DMRPACKET_DATA_TYPE_CSBK: return IPSCPACKET_SLOT_TYPE_CSBK;
		case DMRPACKET_DATA_TYPE_DATA_HEADER: return IPSCPACKET_SLOT_TYPE_DATA_HEADER;
		case DMRPACKET_DATA_TYPE_RATE_12_DATA: return IPSCPACKET_SLOT_TYPE_RATE_12_DATA;
		case DMRPACKET_DATA_TYPE_RATE_34_DATA: return IPSCPACKET_SLOT_TYPE_RATE_34_DATA;
		default: return IPSCPACKET_SLOT_TYPE_UNKNOWN;
	}
}

static void ipscpacket_swap_payload_bytes(ipscpacket_payload_t *payload) {
	uint8_t i;
	uint8_t temp_byte;

	if (payload == NULL)
		return;

	// Swapping the bytes.
	for (i = 0; i < sizeof(ipscpacket_payload_t)-1; i += 2) {
		temp_byte = payload->bytes[i];
		payload->bytes[i] = payload->bytes[i+1];
		payload->bytes[i+1] = temp_byte;
	}
}

// Decodes the UDP packet given in udp_packet to ipsc_packet,
// returns 1 if decoding was successful, otherwise returns 0.
flag_t ipscpacket_decode(struct ip *ippacket, struct udphdr *udppacket, ipscpacket_t *ipscpacket, flag_t packet_from_us) {
	ipscpacket_payload_raw_t *ipscpacket_raw = (ipscpacket_payload_raw_t *)((uint8_t *)udppacket + sizeof(struct udphdr));
	int ipscpacket_raw_length = 0;
	int i;
	loglevel_t loglevel;

	if (ippacket == NULL || udppacket == NULL || ipscpacket == NULL)
		return 0;

	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	ipscpacket_raw_length = ntohs(udppacket->len)-sizeof(struct udphdr);
	if (ipscpacket_raw_length != IPSC_PACKET_SIZE1 && ipscpacket_raw_length != IPSC_PACKET_SIZE2) {
		//console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, packet size is %u not %u or %u bytes.\n",
		//	ipscpacket_raw_length, IPSC_PACKET_SIZE1, IPSC_PACKET_SIZE2);
		return 0;
	}

	loglevel = console_get_loglevel();

	if (loglevel.flags.debug && loglevel.flags.ipsc) {
		if (!loglevel.flags.comm_ip && !loglevel.flags.dmrlc)
			log_print_separator();

		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket [%s", repeaters_get_display_string_for_ip(&ippacket->ip_src));
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "->%s]: decoding: ", repeaters_get_display_string_for_ip(&ippacket->ip_dst));
		for (i = 0; i < ipscpacket_raw_length; i++)
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "%.2x ", *((uint8_t *)ipscpacket_raw+i));
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "\n");
	}

	if (!packet_from_us && ipscpacket_raw->udp_source_port != udppacket->source && ipscpacket_raw->slot_type != IPSCPACKET_SLOT_TYPE_IPSC_SYNC) {
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

	if (ipscpacket_raw->calltype != DMR_CALL_TYPE_PRIVATE && ipscpacket_raw->calltype != DMR_CALL_TYPE_GROUP) {
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "ipscpacket: decode failed, invalid call type (%.2x)\n", ipscpacket_raw->calltype);
		return 0;
	}

	ipscpacket->seq = ipscpacket_raw->seq;
	ipscpacket->slot_type = ipscpacket_raw->slot_type;
	ipscpacket->call_type = ipscpacket_raw->calltype;
	ipscpacket->dst_id = ipscpacket_raw->dst_id_raw3 << 16 | ipscpacket_raw->dst_id_raw2 << 8 | ipscpacket_raw->dst_id_raw1;
	ipscpacket->src_id = ipscpacket_raw->src_id_raw3 << 16 | ipscpacket_raw->src_id_raw2 << 8 | ipscpacket_raw->src_id_raw1;
	memcpy(ipscpacket->payload.bytes, ipscpacket_raw->payload.bytes, sizeof(ipscpacket_payload_t));
	ipscpacket_swap_payload_bytes(&ipscpacket->payload);
	base_bytestobits(ipscpacket->payload.bytes, sizeof(ipscpacket_payload_t)-1, ipscpacket->payload_bits.bits, sizeof(dmrpacket_payload_bits_t));

	if (loglevel.flags.ipsc && loglevel.flags.debug) {
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  udp source port: %u\n", ntohs(ipscpacket_raw->udp_source_port));
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved1: 0x%.2x%.2x\n", ipscpacket_raw->reserved1[0], ipscpacket_raw->reserved1[1]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  seq: %u\n", ipscpacket_raw->seq);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved2: 0x");
		for (i = 0; i < sizeof(ipscpacket_raw->reserved2); i++)
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "%.2x", ipscpacket_raw->reserved2[i]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "\n");
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  packet type: 0x%.2x\n", ipscpacket_raw->packet_type);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved3: 0x");
		for (i = 0; i < sizeof(ipscpacket_raw->reserved3); i++)
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "%.2x", ipscpacket_raw->reserved3[i]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "\n");
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  timeslot raw: 0x%.4x\n", ipscpacket_raw->timeslot_raw);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  slot type: 0x%.4x\n", ipscpacket_raw->slot_type);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  delimiter: 0x%.4x\n", ipscpacket_raw->delimiter);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  frame type: 0x%.4x\n", ipscpacket_raw->frame_type);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved4 0x%.2x%.2x\n", ipscpacket_raw->reserved4[0], ipscpacket_raw->reserved4[1]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  payload (swapped): ");
		for (i = 0; i < sizeof(ipscpacket_payload_t); i++)
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "%.2x", ipscpacket->payload.bytes[i]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "\n");
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  payload (bits): ");
		for (i = 0; i < sizeof(dmrpacket_payload_bits_t); i++)
			console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "%u", ipscpacket->payload_bits.bits[i]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "\n");
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved5: 0x%.2x%.2x\n", ipscpacket_raw->reserved5[0], ipscpacket_raw->reserved5[1]);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  call type: 0x%.2x\n", ipscpacket_raw->calltype);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved6: 0x%.2x\n", ipscpacket_raw->reserved6);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  dst id raw: 0x%.2x%.2x%.2x\n", ipscpacket_raw->dst_id_raw1, ipscpacket_raw->dst_id_raw2, ipscpacket_raw->dst_id_raw3);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved7: 0x%.2x\n", ipscpacket_raw->reserved7);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  src id raw: 0x%.2x%.2x%.2x\n", ipscpacket_raw->src_id_raw1, ipscpacket_raw->src_id_raw2, ipscpacket_raw->src_id_raw3);
		console_log(LOGLEVEL_IPSC LOGLEVEL_DEBUG "  reserved8: 0x%.2x\n", ipscpacket_raw->reserved8);
	}

	return 1;
}

flag_t ipscpacket_heartbeat_decode(struct udphdr *udppacket) {
	static uint8_t heartbeat[] = { 0x00, 0x00, 0x00, 0x14 };

	if (udppacket == NULL)
		return 0;

	if (memcmp((uint8_t *)udppacket + sizeof(struct udphdr) + 5, heartbeat, sizeof(heartbeat)) == 0)
		return 1;
	return 0;
}

// Constructs a raw IPSC packet (IP packet) from given raw IPSC packet payload.
ipscpacket_raw_t *ipscpacket_construct_raw_packet(struct in_addr *dst_addr, ipscpacket_payload_raw_t *ipscpacket_payload_raw) {
	static ipscpacket_raw_t ipscpacket_raw;
	struct iphdr *ip_packet = (struct iphdr *)ipscpacket_raw.bytes;
	struct udphdr *udp_packet = (struct udphdr *)(ipscpacket_raw.bytes+20);
	struct in_addr *master_ip_addr = config_get_masteripaddr();

	if (master_ip_addr == NULL) {
		console_log("ipscpacket error: can't construct raw packet for sending as master ip address is not set in the config\n");
		return NULL;
	}

	memcpy(&ip_packet->saddr, master_ip_addr, sizeof(struct in_addr));
	free(master_ip_addr);
	memcpy(&ip_packet->daddr, dst_addr, sizeof(struct in_addr));
	ip_packet->ihl = 5;
	ip_packet->version = 4;
	ip_packet->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(ipscpacket_payload_raw_t));
	ip_packet->id = htonl(7777);
	ip_packet->ttl = 255;
	ip_packet->protocol = IPPROTO_UDP;
	ip_packet->check = comm_calcipheaderchecksum((struct ip *)ip_packet);
	udp_packet->source = htons(62006);
	udp_packet->dest = htons(62006);
	udp_packet->len = htons(sizeof(struct udphdr) + sizeof(ipscpacket_payload_raw_t));
	memcpy(ipscpacket_raw.bytes+20+8, ipscpacket_payload_raw, sizeof(ipscpacket_payload_raw_t));
	udp_packet->check = comm_calcudpchecksum((struct ip *)ip_packet, udp_packet);

	return &ipscpacket_raw;
}

ipscpacket_payload_raw_t *ipscpacket_construct_raw_payload(uint8_t seqnum, dmr_timeslot_t ts, ipscpacket_slot_type_t slot_type,
	dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, ipscpacket_payload_t *payload) {

	static ipscpacket_payload_raw_t ipscpacket_raw;

	if (ts < 0 || ts > 1 || calltype < 0 || calltype > 1)
		return NULL;

	memset(&ipscpacket_raw, 0, sizeof(ipscpacket_payload_raw_t));

	ipscpacket_raw.reserved3[1] = 0x05;
	ipscpacket_raw.reserved3[2] = 0x01;
	ipscpacket_raw.reserved3[3] = ts+1;
	ipscpacket_raw.timeslot_raw = (ts == 0 ? 0x1111 : 0x2222);
	ipscpacket_raw.slot_type = slot_type;
	ipscpacket_raw.delimiter = 0x1111;
	ipscpacket_raw.reserved4[0] = 0x40;
	ipscpacket_raw.reserved5[0] = 0x63;
	ipscpacket_raw.reserved5[1] = 0x02;
	ipscpacket_raw.calltype = calltype;
	ipscpacket_raw.dst_id_raw1 = (dstid & 0xff);
	ipscpacket_raw.dst_id_raw2 = ((dstid >> 8) & 0xff);
	ipscpacket_raw.dst_id_raw3 = ((dstid >> 16) & 0xff);
	ipscpacket_raw.src_id_raw1 = (srcid & 0xff);
	ipscpacket_raw.src_id_raw2 = ((srcid >> 8) & 0xff);
	ipscpacket_raw.src_id_raw3 = ((srcid >> 16) & 0xff);
	if (payload != NULL) {
		memcpy(&ipscpacket_raw.payload.bytes, payload, sizeof(ipscpacket_payload_t));
		ipscpacket_swap_payload_bytes(&ipscpacket_raw.payload);
	}
	if (slot_type == IPSCPACKET_SLOT_TYPE_IPSC_SYNC) {
		ipscpacket_raw.packet_type = 0x02;
		ipscpacket_raw.frame_type = 0x6666;
	} else {
		ipscpacket_raw.udp_source_port = htons(62006);
		ipscpacket_raw.seq = seqnum;
		ipscpacket_raw.reserved1[1] = 0x50;
		ipscpacket_raw.reserved2[0] = 0xe0;
		ipscpacket_raw.packet_type = 0x01;
		ipscpacket_raw.frame_type = 0xbbbb;
	}
	ipscpacket_raw.reserved4[1] = 0x5c;

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
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA));
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
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA));
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_voice_frame(ipscpacket_slot_type_t slot_type, dmrpacket_payload_voice_bits_t *voice_bits, vbptc_16_11_t *emb_signalling_lc_vbptc_bits) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_bits_t payload_bits;
	dmrpacket_emb_signalling_lc_fragment_bits_t emb_signalling_lc_fragment_bits = { .bits = { 0, } };

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));

	dmrpacket_insert_voice_bits(&payload_bits, voice_bits);

	switch (slot_type) {
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C:
			dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE));
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_FIRST_FRAGMENT));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, 0, emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_CONTINUATION));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t), emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_F:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_CONTINUATION));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t)*2, emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_LAST_FRAGMENT));
			vbptc_16_11_get_interleaved_bits(emb_signalling_lc_vbptc_bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t)*3, emb_signalling_lc_fragment_bits.bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits);
			break;
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B:
			dmrpacket_emb_insert_bits(&payload_bits, dmrpacket_emb_construct_bits(DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT));
			dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(&payload_bits, &emb_signalling_lc_fragment_bits); // Note that this is a null fragment.
			break;
	}

	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_csbk(dmrpacket_csbk_t *csbk) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_info_bits_t *payload_info_bits;
	dmrpacket_payload_bits_t payload_bits;

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));
	payload_info_bits = dmrpacket_data_bptc_interleave(bptc_196_96_generate(dmrpacket_csbk_construct(csbk)));
	dmrpacket_insert_info_bits(&payload_bits, payload_info_bits);
	dmrpacket_slot_type_insert_bits(&payload_bits, dmrpacket_slot_type_construct_bits(1, DMRPACKET_DATA_TYPE_CSBK));
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA));
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_data_header(dmrpacket_data_header_t *data_header) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_info_bits_t *payload_info_bits;
	dmrpacket_payload_bits_t payload_bits;

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));
	payload_info_bits = dmrpacket_data_bptc_interleave(bptc_196_96_generate(dmrpacket_data_header_construct(data_header, 0)));
	dmrpacket_insert_info_bits(&payload_bits, payload_info_bits);
	dmrpacket_slot_type_insert_bits(&payload_bits, dmrpacket_slot_type_construct_bits(1, DMRPACKET_DATA_TYPE_DATA_HEADER));
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA));
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_data_block_rate_34(dmrpacket_data_block_t *data_block) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_info_bits_t *payload_info_bits;
	dmrpacket_payload_bits_t payload_bits;
	dmrpacket_data_block_bytes_t *data_block_bytes;
	dmrpacket_data_binary_t data_block_binary;
	trellis_tribits_t *tribits;
	trellis_constellationpoints_t *constellationpoints;
	trellis_dibits_t *dibits;

	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));

	data_block_bytes = dmrpacket_data_construct_block_bytes(data_block, 1);
	base_bytestobits(data_block_bytes->bytes, sizeof(dmrpacket_data_block_bytes_t), data_block_binary.bits, sizeof(dmrpacket_data_binary_t));

	tribits = trellis_construct_tribits(&data_block_binary);
	constellationpoints = trellis_construct_constellationpoints(tribits);
	dibits = trellis_construct_deinterleaved_dibits(constellationpoints);
	payload_info_bits = trellis_construct_payload_info_bits(trellis_interleave_dibits(dibits));
	dmrpacket_insert_info_bits(&payload_bits, payload_info_bits);
	dmrpacket_slot_type_insert_bits(&payload_bits, dmrpacket_slot_type_construct_bits(1, DMRPACKET_DATA_TYPE_RATE_34_DATA));
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA));
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_data_block_rate_12(dmrpacket_data_block_t *data_block) {
	static ipscpacket_payload_t ipscpacket_payload;
	dmrpacket_payload_info_bits_t *payload_info_bits;
	dmrpacket_payload_bits_t payload_bits;
	bptc_196_96_data_bits_t data_bits;

	memset(data_bits.bits, 0, sizeof(bptc_196_96_data_bits_t));
	base_bytestobits(data_block->data, data_block->data_length, data_bits.bits, sizeof(bptc_196_96_data_bits_t));
	payload_info_bits = dmrpacket_data_bptc_interleave(bptc_196_96_generate(&data_bits));
	dmrpacket_insert_info_bits(&payload_bits, payload_info_bits);
	dmrpacket_slot_type_insert_bits(&payload_bits, dmrpacket_slot_type_construct_bits(1, DMRPACKET_DATA_TYPE_RATE_12_DATA));
	dmrpacket_sync_insert_bits(&payload_bits, dmrpacket_sync_construct_bits(DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA));
	memset(ipscpacket_payload.bytes, 0, sizeof(ipscpacket_payload_t));
	base_bitstobytes(payload_bits.bits, sizeof(dmrpacket_payload_bits_t), ipscpacket_payload.bytes, sizeof(ipscpacket_payload_t));

	return &ipscpacket_payload;
}

ipscpacket_payload_t *ipscpacket_construct_payload_ipsc_sync(dmr_timeslot_t ts, dmr_id_t dstid, dmr_id_t srcid) {
	static ipscpacket_payload_t ipscpacket_payload = { .bytes = { 0x00, 0x43, 0x00, 0x48, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x61, 0x00, 0x20, 0x00, 0xf9, 0x00, 0x6d, 0x00,
		0x91, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f } };

	ipscpacket_payload.bytes[7] = (srcid >> 16) & 0xff;
	ipscpacket_payload.bytes[9] = (srcid >> 8) & 0xff;
	ipscpacket_payload.bytes[11] = srcid & 0xff;
	ipscpacket_payload.bytes[13] = (dstid >> 16) & 0xff;
	ipscpacket_payload.bytes[15] = (dstid >> 8) & 0xff;
	ipscpacket_payload.bytes[17] = dstid & 0xff;

	return &ipscpacket_payload;
}
