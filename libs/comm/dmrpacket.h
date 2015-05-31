#ifndef DMRPACKET_H_
#define DMRPACKET_H_

#include <libs/base/types.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

typedef uint8_t dmr_packet_type_t;
typedef uint8_t dmr_timeslot_t;
typedef uint16_t dmr_slot_type_t;
typedef uint16_t dmr_frame_type_t;
typedef uint8_t dmr_call_type_t;
typedef uint32_t dmr_id_t;

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

#endif
