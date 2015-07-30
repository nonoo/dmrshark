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

#include <libs/daemon/console.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

typedef struct __attribute__((packed)) {
	uint16_t port;
	uint8_t reserved1[2];
	uint8_t seq;
	uint8_t reserved2[3];
	uint8_t packet_type;
	uint8_t reserved3[7];
	uint16_t timeslot_raw; // 0x1111 if TS1, 0x2222 if TS2
	uint16_t slot_type;
	uint16_t delimiter; // Always 0x1111.
	uint16_t frame_type;
	uint8_t reserved4[2];
	uint8_t payload[IPSCPACKET_PAYLOAD_SIZE];
	uint8_t reserved5[2];
	uint8_t calltype; // 0x00 - private call, 0x01 - group call
	uint8_t reserved6;
	uint8_t dst_id_raw1;
	uint8_t dst_id_raw2;
	uint8_t dst_id_raw3;
	uint8_t reserved7;
	uint8_t src_id_raw1;
	uint8_t src_id_raw2;
	uint8_t src_id_raw3;
} ipscpacket_raw_t;

#define IPSC_PACKET_SIZE1 72
#define IPSC_PACKET_SIZE2 103

char *ipscpacket_get_readable_packet_type(ipscpacket_type_t packet_type) {
	switch (packet_type) {
		case IPSCPACKET_PACKET_TYPE_VOICE: return "voice";
		case IPSCPACKET_PACKET_TYPE_START_OF_TRANSMISSION: return "sync/start of transmission";
		case IPSCPACKET_PACKET_TYPE_END_OF_TRANSMISSION: return "end of transmission";
		case IPSCPACKET_PACKET_TYPE_HYTERA_DATA: return "hytera data";
		default: return "unknown";
	}
}

char *ipscpacket_get_readable_slot_type(ipscpacket_slot_type_t slot_type) {
	switch (slot_type) {
		case IPSCPACKET_SLOT_TYPE_CALL_START: return "call start";
		case IPSCPACKET_SLOT_TYPE_START: return "start";
		case IPSCPACKET_SLOT_TYPE_CALL_END: return "call end";
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

char *ipscpacket_get_readable_frame_type(ipscpacket_frame_type_t frame_type) {
	switch (frame_type) {
		case IPSCPACKET_FRAME_TYPE_GENERAL: return "general";
		case IPSCPACKET_FRAME_TYPE_VOICE_SYNC: return "voice sync";
		case IPSCPACKET_FRAME_TYPE_DATA_START: return "data start";
		case IPSCPACKET_FRAME_TYPE_VOICE: return "voice";
		default: return "unknown";
	}
}

// Decodes the UDP packet given in udp_packet to ipsc_packet,
// returns 1 if decoding was successful, otherwise returns 0.
flag_t ipscpacket_decode(struct udphdr *udppacket, ipscpacket_t *ipscpacket) {
	ipscpacket_raw_t *ipscpacket_raw = (ipscpacket_raw_t *)((uint8_t *)udppacket + sizeof(struct udphdr));
	int ipscpacket_raw_length = 0;
	int i;
	loglevel_t loglevel;

	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	ipscpacket_raw_length = ntohs(udppacket->len)-sizeof(struct udphdr);
	if (ipscpacket_raw_length != IPSC_PACKET_SIZE1 && ipscpacket_raw_length != IPSC_PACKET_SIZE2) {
		//console_log(LOGLEVEL_DEBUG "ipscpacket: decode failed, packet size is %u not %u or %u bytes.\n",
		//	ipscpacket_raw_length, IPSC_PACKET_SIZE1, IPSC_PACKET_SIZE2);
		return 0;
	}

	loglevel = console_get_loglevel();
	if (loglevel.flags.debug && loglevel.flags.comm_dmr) {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "ipscpacket: decoding: ");
		for (i = 0; i < ipscpacket_raw_length; i++)
			console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "%.2x ", *((uint8_t *)ipscpacket_raw+i));
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "\n");
	}

	/*if (ipscpacket_raw->delimiter != 0x1111) {
		console_log(LOGLEVEL_DEBUG "ipscpacket: decode failed, delimiter mismatch (it's %.4x, should be 0x1111)\n",
			ipscpacket_raw->delimiter);
		return 0;
	}*/

	ipscpacket->packet_type = ipscpacket_raw->packet_type;
	if (ipscpacket_raw->timeslot_raw == 0x1111)
		ipscpacket->timeslot = 1;
	else if (ipscpacket_raw->timeslot_raw == 0x2222)
		ipscpacket->timeslot = 2;
	else {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "ipscpacket: decode failed, invalid timeslot (%.4x)\n", ipscpacket_raw->timeslot_raw);
		return 0;
	}

	ipscpacket->slot_type = ipscpacket_raw->slot_type;
	ipscpacket->frame_type = ipscpacket_raw->frame_type;
	ipscpacket->call_type = ipscpacket_raw->calltype;
	ipscpacket->dst_id = ipscpacket_raw->dst_id_raw3 << 16 | ipscpacket_raw->dst_id_raw2 << 8 | ipscpacket_raw->dst_id_raw1;
	ipscpacket->src_id = ipscpacket_raw->src_id_raw3 << 16 | ipscpacket_raw->src_id_raw2 << 8 | ipscpacket_raw->src_id_raw1;
	memcpy(ipscpacket->payload, (uint8_t *)ipscpacket_raw->payload, IPSCPACKET_PAYLOAD_SIZE);

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

// Swaps given payload bytes and then converts them to an uint8_t array of bits.
dmrpacket_payload_bits_t *ipscpacket_convertpayloadtobits(uint8_t *ipscpacket_payload) {
	static dmrpacket_payload_bits_t payload_bits;
	uint8_t swapped_bytes[IPSCPACKET_PAYLOAD_SIZE] = {0,};
	int i, j;

	if (ipscpacket_payload == NULL)
		return NULL;

	// Swapping the bytes.
	for (i = 0; i < IPSCPACKET_PAYLOAD_SIZE-1; i += 2) {
		swapped_bytes[i] = *(ipscpacket_payload + i + 1);
		swapped_bytes[i+1] = *(ipscpacket_payload + i);
	}

	return &payload_bits;
}
