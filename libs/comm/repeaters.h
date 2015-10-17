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

#include "ipscpacket.h"

#include <libs/base/dmr.h>
#include <libs/dmrpacket/dmrpacket-data-header.h>
#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/coding/vbptc-16-11.h>
#include <libs/voicestreams/voicestreams.h>

#include <arpa/inet.h>
#include <time.h>

#define REPEATER_SLOT_STATE_IDLE					0
#define REPEATER_SLOT_STATE_VOICE_CALL_RUNNING		1
#define REPEATER_SLOT_STATE_DATA_CALL_RUNNING		2
typedef uint8_t repeater_slot_state_t;

typedef struct repeater_echo_buf_st {
	dmrpacket_payload_voice_bytes_t voice_bytes;

	struct repeater_echo_buf_st *next;
} repeater_echo_buf_t;

typedef struct {
	repeater_slot_state_t state;
	int rssi;
	int avg_rssi;
	time_t last_call_or_data_packet_received_at;
	time_t call_started_at;
	time_t call_ended_at;
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
	dmrpacket_data_header_t data_packet_header;
	flag_t data_packet_header_valid; // If it's not valid, we won't process received data packets.
	dmrpacket_data_block_t data_blocks[64];
	uint8_t data_blocks_received;
	uint8_t data_blocks_expected;
	uint8_t full_message_block_count;
	dmrpacket_data_header_seqnum_t rx_seqnum;
	uint8_t selective_ack_requests_sent;
	voicestream_t *voicestream;
	uint8_t ipsc_last_received_seqnum;

	dmr_id_t decoded_data_dstid;
	dmr_id_t decoded_data_srcid;
	char decoded_data[DMRPACKET_DATA_MAX_DECODED_DATA_SIZE];
	dmr_data_type_t decoded_data_type;
	flag_t decoded_data_acked;

	// These variables are used for sending IPSC packets to the repeater.
	ipscrawpacketbuf_t *ipsc_tx_rawpacketbuf;
	uint8_t ipsc_tx_seqnum;
	uint8_t ipsc_tx_voice_frame_num;
	vbptc_16_11_t ipsc_tx_emb_sig_lc_vbptc_storage;

	// This holds the last received frame's number in a voice superframe if we are in a call.
	uint8_t voice_frame_num;
	// This is where we store received embedded signalling lc fragments.
	vbptc_16_11_t emb_sig_lc_vbptc_storage;

	repeater_echo_buf_t *echo_buf_first_entry;
	repeater_echo_buf_t *echo_buf_last_entry;
} repeater_slot_t;

typedef struct repeater_st {
	struct in_addr ipaddr;
	time_t last_active_time;
	flag_t snmpignored;
	time_t last_repeaterinfo_request_time;
	struct timeval last_rssi_request_time;
	dmr_timeslot_t last_ipsc_packet_sent_from_slot;
	struct timeval last_ipsc_packet_sent_time;
	dmr_id_t id;
	char type[25];
	char fwversion[25];
	char callsign[25];
	char callsign_lowercase[25];
	int dlfreq;
	int ulfreq;
	float psuvoltage;
	float patemperature;
	float vswr;
	float txfwdpower;
	float txrefpower;
	repeater_slot_t slot[2];
	time_t auto_rssi_update_enabled_at;

	struct repeater_st *next;
	struct repeater_st *prev;
} repeater_t;

repeater_t *repeaters_get(void);

char *repeaters_get_display_string_for_ip(struct in_addr *ipaddr);
char *repeaters_get_display_string(repeater_t *repeater);

repeater_t *repeaters_findbyip(struct in_addr *ipaddr);
repeater_t *repeaters_findbyhost(char *host);
repeater_t *repeaters_findbycallsign(char *callsign);
repeater_t *repeaters_get_active(dmr_id_t src_id, dmr_id_t dst_id, dmr_call_type_t call_type);
repeater_t *repeaters_add(struct in_addr *ipaddr);
void repeaters_list(void);

void repeaters_state_change(repeater_t *repeater, dmr_timeslot_t timeslot, repeater_slot_state_t new_state);
void repeaters_add_to_ipsc_packet_buffer(repeater_t *repeater, dmr_timeslot_t ts, ipscpacket_raw_t *ipscpacket_raw);

void repeaters_start_voice_call(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid);
void repeaters_play_ambe_data(dmrpacket_payload_voice_bytes_t *voice_bytes, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid);
void repeaters_end_voice_call(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid);
void repeaters_play_ambe_file(char *ambe_file_name, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid);

void repeaters_free_echo_buf(repeater_t *repeater, dmr_timeslot_t ts);
void repeaters_play_and_free_echo_buf(repeater_t *repeater, dmr_timeslot_t ts);
void repeaters_store_voice_frame_to_echo_buf(repeater_t *repeater, ipscpacket_t *ipscpacket);

void repeaters_send_data_packet(repeater_t *repeater, dmr_timeslot_t ts, flag_t *selective_blocks, uint8_t selective_blocks_size, dmrpacket_data_packet_t *data_packet);
void repeaters_send_broadcast_data_packet(dmrpacket_data_packet_t *data_packet);

void repeaters_process(void);
void repeaters_deinit(void);

#endif
