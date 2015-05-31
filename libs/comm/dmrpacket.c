#include <config/defaults.h>

#include "dmrpacket.h"

#include <libs/daemon/console.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

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
	uint8_t reserved4[3];
	uint8_t payload[33];
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
} dmr_packet_raw_t;

#define DMR_PACKET_SIZE 72

char *dmrpacket_get_readable_packet_type(dmr_packet_type_t packet_type) {
	switch (packet_type) {
		case 0x01: return "voice";
		case 0x02: return "sync/start of transmission";
		case 0x03: return "end of transmission";
		case 0x41: return "hytera data";
		case 0x62: return "signaling";
		case 0x42:
		case 0x22:
		case 0xe2: return "sync";
		default: return "unknown";
	}
}

char *dmrpacket_get_readable_slot_type(dmr_slot_type_t slot_type) {
	switch (slot_type) {
		case 0xDDDD: return "call start";
		case 0xEEEE: return "start";
		case 0x2222: return "call end";
		case 0x3333: return "csbk"; // Control Signaling Block
		case 0x4444: return "data header";
		case 0x5555: return "1/2 rate data";
		case 0x6666: return "3/4 rate data";
		case 0xBBBB: return "voice data 1";
		case 0xCCCC: return "voice data 2";
		case 0x7777: return "voice data 3";
		case 0x8888: return "voice data 4";
		case 0x9999: return "voice data 5";
		case 0xAAAA: return "voice data 6";
		default: return "unknown";
	}
}

char *dmrpacket_get_readable_frame_type(dmr_frame_type_t frame_type) {
	switch (frame_type) {
		case 0x0000: return "general";
		case 0x1111: return "voice sync";
		case 0x6666: return "data start";
		case 0x9999: return "voice";
		default: return "unknown";
	}
}

char *dmrpacket_get_readable_call_type(dmr_call_type_t call_type) {
	switch (call_type) {
		case 0x00: return "private";
		case 0x01: return "group";
		default: return "unknown";
	}
}

// Decodes the UDP packet given in udp_packet to dmr_packet,
// returns 1 if decoding was successful, otherwise returns 0.
flag_t dmrpacket_decode(struct udphdr *udp_packet, dmr_packet_t *dmr_packet) {
	dmr_packet_raw_t *dmr_packet_raw = (dmr_packet_raw_t *)((uint8_t *)udp_packet + sizeof(struct udphdr));
	int dmr_packet_raw_length = 0;
	int i;
	loglevel_t loglevel;

	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	dmr_packet_raw_length = ntohs(udp_packet->len)-sizeof(struct udphdr);
	if (dmr_packet_raw_length != DMR_PACKET_SIZE) {
		console_log(LOGLEVEL_DEBUG "dmrpacket: decode failed, packet size not %u bytes.\n", DMR_PACKET_SIZE);
		return 0;
	}

	loglevel = console_get_loglevel();
	if (loglevel.flags.debug) {
		console_log(LOGLEVEL_DEBUG "dmrpacket: decoding: ");
		for (i = 0; i < dmr_packet_raw_length; i++)
			console_log(LOGLEVEL_DEBUG "%.2x ", *((uint8_t *)dmr_packet_raw+i));
		console_log(LOGLEVEL_DEBUG "\n");
	}

	if (dmr_packet_raw->delimiter != 0x1111) {
		console_log(LOGLEVEL_DEBUG "dmrpacket: decode failed, delimiter mismatch (it's %.4x, should be 0x1111)\n",
			dmr_packet_raw->delimiter);
		return 0;
	}

	dmr_packet->packet_type = dmr_packet_raw->packet_type;
	if (dmr_packet_raw->timeslot_raw == 0x1111)
		dmr_packet->timeslot = 1;
	else if (dmr_packet_raw->timeslot_raw == 0x2222)
		dmr_packet->timeslot = 2;
	else {
		console_log(LOGLEVEL_DEBUG "dmrpacket: decode failed, invalid timeslot (%.4x)\n", dmr_packet_raw->timeslot_raw);
		return 0;
	}

	dmr_packet->slot_type = dmr_packet_raw->slot_type;
	dmr_packet->frame_type = dmr_packet_raw->frame_type;
	dmr_packet->call_type = dmr_packet_raw->calltype;
	dmr_packet->dst_id = dmr_packet_raw->dst_id_raw3 << 16 | dmr_packet_raw->dst_id_raw2 << 8 | dmr_packet_raw->dst_id_raw1;
	dmr_packet->src_id = dmr_packet_raw->src_id_raw3 << 16 | dmr_packet_raw->src_id_raw2 << 8 | dmr_packet_raw->src_id_raw1;

	return 1;
}
