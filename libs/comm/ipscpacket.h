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

#include <netinet/udp.h>

#define IPSCPACKET_PAYLOAD_SIZE							34

#define IPSCPACKET_PACKET_TYPE_VOICE					0x01
#define IPSCPACKET_PACKET_TYPE_START_OF_TRANSMISSION	0x02
#define IPSCPACKET_PACKET_TYPE_END_OF_TRANSMISSION		0x03
#define IPSCPACKET_PACKET_TYPE_HYTERA_DATA				0x41
typedef uint8_t ipscpacket_type_t;

#define IPSCPACKET_SLOT_TYPE_CALL_START					0xDDDD
#define IPSCPACKET_SLOT_TYPE_START						0xEEEE
#define IPSCPACKET_SLOT_TYPE_CALL_END					0x2222
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
typedef uint16_t ipscpacket_slot_type_t;

#define IPSCPACKET_FRAME_TYPE_GENERAL					0x0000
#define IPSCPACKET_FRAME_TYPE_VOICE_SYNC				0x1111
#define IPSCPACKET_FRAME_TYPE_DATA_START				0x6666
#define IPSCPACKET_FRAME_TYPE_VOICE						0x9999
typedef uint16_t ipscpacket_frame_type_t;

typedef struct {
	ipscpacket_type_t packet_type;
	dmr_timeslot_t timeslot;
	ipscpacket_slot_type_t slot_type;
	ipscpacket_frame_type_t frame_type;
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
	uint8_t payload[IPSCPACKET_PAYLOAD_SIZE];
} ipscpacket_t;

char *ipscpacket_get_readable_packet_type(ipscpacket_type_t packet_type);
char *ipscpacket_get_readable_slot_type(ipscpacket_slot_type_t slot_type);
char *ipscpacket_get_readable_frame_type(ipscpacket_frame_type_t frame_type);

flag_t ipscpacket_decode(struct udphdr *udppacket, ipscpacket_t *ipscpacket);
flag_t ipscpacket_heartbeat_decode(struct udphdr *udppacket);

dmrpacket_payload_bits_t *ipscpacket_convertpayloadtobits(uint8_t *ipscpacket_payload);

#endif
