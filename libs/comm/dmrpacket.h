#ifndef DMRPACKET_H_
#define DMRPACKET_H_

#include <libs/base/types.h>

#include <netinet/udp.h>

typedef uint8_t dmr_packet_type_t;
typedef uint8_t dmr_timeslot_t;
typedef uint16_t dmr_slot_type_t;
typedef uint16_t dmr_frame_type_t;
typedef uint8_t dmr_call_type_t;
typedef uint32_t dmr_id_t;

#define DMRPACKET_PACKET_TYPE_VOICE					0x01
#define DMRPACKET_PACKET_TYPE_START_OF_TRANSMISSION	0x02
#define DMRPACKET_PACKET_TYPE_END_OF_TRANSMISSION	0x03
#define DMRPACKET_PACKET_TYPE_HYTERA_DATA			0x41

#define DMRPACKET_SLOT_TYPE_CALL_START				0xDDDD
#define DMRPACKET_SLOT_TYPE_START					0xEEEE
#define DMRPACKET_SLOT_TYPE_CALL_END				0x2222
#define DMRPACKET_SLOT_TYPE_CSBK					0x3333
#define DMRPACKET_SLOT_TYPE_DATA_HEADER				0x4444
#define DMRPACKET_SLOT_TYPE_1_2_RATE_DATA			0x5555
#define DMRPACKET_SLOT_TYPE_3_4_RATE_DATA			0x6666
#define DMRPACKET_SLOT_TYPE_VOICE_DATA_1			0xBBBB
#define DMRPACKET_SLOT_TYPE_VOICE_DATA_2			0xCCCC
#define DMRPACKET_SLOT_TYPE_VOICE_DATA_3			0x7777
#define DMRPACKET_SLOT_TYPE_VOICE_DATA_4			0x8888
#define DMRPACKET_SLOT_TYPE_VOICE_DATA_5			0x9999
#define DMRPACKET_SLOT_TYPE_VOICE_DATA_6			0xAAAA

#define DMRPACKET_FRAME_TYPE_GENERAL				0x0000
#define DMRPACKET_FRAME_TYPE_VOICE_SYNC				0x1111
#define DMRPACKET_FRAME_TYPE_DATA_START				0x6666
#define DMRPACKET_FRAME_TYPE_VOICE					0x9999

#define DMRPACKET_CALL_TYPE_PRIVATE					0x00
#define DMRPACKET_CALL_TYPE_GROUP					0x01

typedef struct {
	dmr_packet_type_t packet_type;
	dmr_timeslot_t timeslot;
	dmr_slot_type_t slot_type;
	dmr_frame_type_t frame_type;
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
} dmr_packet_t;

char *dmrpacket_get_readable_packet_type(dmr_packet_type_t packet_type);
char *dmrpacket_get_readable_slot_type(dmr_slot_type_t slot_type);
char *dmrpacket_get_readable_frame_type(dmr_frame_type_t frame_type);
char *dmrpacket_get_readable_call_type(dmr_call_type_t call_type);
flag_t dmrpacket_decode(struct udphdr *udp_packet, dmr_packet_t *dmr_packet);
flag_t dmrpacket_heartbeat_decode(struct udphdr *udp_packet);

#endif
