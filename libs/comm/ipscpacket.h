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

#ifndef IPSCPACKET_H_
#define IPSCPACKET_H_

#include <libs/base/dmr.h>
#include <libs/dmrpacket/dmrpacket.h>
#include <libs/dmrpacket/dmrpacket-emb.h>
#include <libs/dmrpacket/dmrpacket-csbk.h>
#include <libs/coding/vbptc-16-11.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#define IPSCPACKET_SLOT_TYPE_VOICE_LC_HEADER			0x1111
#define IPSCPACKET_SLOT_TYPE_TERMINATOR_WITH_LC			0x2222
#define IPSCPACKET_SLOT_TYPE_CSBK						0x3333
#define IPSCPACKET_SLOT_TYPE_DATA_HEADER				0x4444
#define IPSCPACKET_SLOT_TYPE_1_2_RATE_DATA				0x5555
#define IPSCPACKET_SLOT_TYPE_3_4_RATE_DATA				0x6666
#define IPSCPACKET_SLOT_TYPE_VOICE_DATA_A				0xBBBB
#define IPSCPACKET_SLOT_TYPE_VOICE_DATA_B				0xCCCC
#define IPSCPACKET_SLOT_TYPE_VOICE_DATA_C				0x7777
#define IPSCPACKET_SLOT_TYPE_VOICE_DATA_D				0x8888
#define IPSCPACKET_SLOT_TYPE_VOICE_DATA_E				0x9999
#define IPSCPACKET_SLOT_TYPE_VOICE_DATA_F				0xAAAA
#define IPSCPACKET_SLOT_TYPE_IPSC_SYNC					0xEEEE
typedef uint16_t ipscpacket_slot_type_t;

typedef struct {
	uint8_t bytes[34];
} ipscpacket_payload_t;

typedef struct __attribute__((packed)) {
	uint16_t udp_source_port;
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
	ipscpacket_payload_t payload;
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
	uint8_t reserved8;
} ipscpacket_payload_raw_t;

typedef struct {
	uint8_t bytes[20+8+sizeof(ipscpacket_payload_raw_t)]; // 20 - ip header, 8 - udp header
} ipscpacket_raw_t;

typedef struct {
	dmr_timeslot_t timeslot;
	ipscpacket_slot_type_t slot_type;
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
	ipscpacket_payload_t payload;
	dmrpacket_payload_bits_t payload_bits;
} ipscpacket_t;

typedef struct ipscrawpacketbuf_st {
	ipscpacket_raw_t ipscpacket_raw;

	struct ipscrawpacketbuf_st *next;
} ipscrawpacketbuf_t;

char *ipscpacket_get_readable_slot_type(ipscpacket_slot_type_t slot_type);

flag_t ipscpacket_decode(struct ip *ippacket, struct udphdr *udppacket, ipscpacket_t *ipscpacket, flag_t packet_from_us);
flag_t ipscpacket_heartbeat_decode(struct udphdr *udppacket);

ipscpacket_raw_t *ipscpacket_construct_raw_packet(struct in_addr *dst_addr, ipscpacket_payload_raw_t *ipscpacket_payload_raw);
ipscpacket_payload_raw_t *ipscpacket_construct_raw_payload(uint8_t seqnum, dmr_timeslot_t ts, ipscpacket_slot_type_t slot_type, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, ipscpacket_payload_t *payload);
ipscpacket_payload_t *ipscpacket_construct_payload_voice_lc_header(dmr_call_type_t calltype, dmr_id_t dst_id, dmr_id_t src_id);
ipscpacket_payload_t *ipscpacket_construct_payload_terminator_with_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id);
ipscpacket_payload_t *ipscpacket_construct_payload_voice_frame(ipscpacket_slot_type_t slot_type, dmrpacket_payload_voice_bits_t *voice_bits, vbptc_16_11_t *emb_signalling_lc_vbptc_bits);
ipscpacket_payload_t *ipscpacket_construct_payload_csbk(dmrpacket_csbk_t *csbk);
ipscpacket_payload_t *ipscpacket_construct_payload_sms_header(dmrpacket_data_header_t *data_header);
ipscpacket_payload_t *ipscpacket_construct_payload_data_block_rate_34(dmrpacket_data_block_t *data_block);
ipscpacket_payload_t *ipscpacket_construct_payload_ipsc_sync(dmr_id_t dstid, dmr_id_t srcid);

#endif
