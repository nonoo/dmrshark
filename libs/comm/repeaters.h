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

#ifndef REPEATERS_H_
#define REPEATERS_H_

#include <libs/base/dmr.h>
#include <libs/dmrpacket/dmrpacket.h>
#include <libs/coding/vbptc-16-11.h>
#include <libs/voicestreams/voicestreams.h>

#include <arpa/inet.h>
#include <time.h>

#define REPEATER_SLOT_STATE_IDLE					0
#define REPEATER_SLOT_STATE_CALL_RUNNING			1
#define REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING	2
typedef uint8_t repeater_slot_state_t;

typedef struct {
	repeater_slot_state_t state;
	int rssi;
	int avg_rssi;
	time_t call_started_at;
	time_t last_packet_received_at;
	time_t call_ended_at;
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
	dmrpacket_data_header_t data_packet_header;
	dmrpacket_data_block_t data_blocks[64];
	int data_blocks_received;
	time_t data_header_received_at;
	voicestream_t *voicestream;
} repeater_slot_t;

typedef struct repeater_st {
	struct in_addr ipaddr;
	time_t last_active_time;
	flag_t snmpignored;
	time_t last_repeaterinfo_request_time;
	struct timeval last_rssi_request_time;
	dmr_id_t id;
	char type[25];
	char fwversion[25];
	char callsign[25];
	char callsign_lowercase[25];
	int dlfreq;
	int ulfreq;
	repeater_slot_t slot[2];
	time_t auto_rssi_update_enabled_at;

	struct repeater_st *next;
	struct repeater_st *prev;
} repeater_t;

char *repeaters_get_display_string_for_ip(struct in_addr *ipaddr);
char *repeaters_get_display_string(repeater_t *repeater);

repeater_t *repeaters_findbyip(struct in_addr *ipaddr);
repeater_t *repeaters_get_active(dmr_id_t src_id, dmr_id_t dst_id, dmr_call_type_t call_type);
repeater_t *repeaters_add(struct in_addr *ipaddr);
void repeaters_list(void);

void repeaters_state_change(repeater_t *repeater, dmr_timeslot_t timeslot, repeater_slot_state_t new_state);

void repeaters_process(void);
void repeaters_deinit(void);

#endif
