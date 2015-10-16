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

#ifndef DATA_PACKET_TXBUF_H_
#define DATA_PACKET_TXBUF_H_

#include "dmr.h"

#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/comm/repeaters.h>

#include <time.h>

typedef struct data_packet_txbuf_st {
	dmrpacket_data_packet_t data_packet;
	time_t added_at;
	uint8_t send_tries;
	uint8_t selective_ack_tries;

	flag_t broadcast_to_all_repeaters; // If 1, it will be sent to all timeslots on all repeaters.
	repeater_t *repeater; // If broadcast is 0, the packet will be sent on this repeater on the given timeslot.
	dmr_timeslot_t ts;

	struct data_packet_txbuf_st *next;
} data_packet_txbuf_t;

void data_packet_txbuf_print_entry(data_packet_txbuf_t *entry);
void data_packet_txbuf_print(void);
void data_packet_txbuf_add(flag_t broadcast_to_all_repeaters, repeater_t *repeater, dmr_timeslot_t ts, dmrpacket_data_packet_t *data_packet);

void data_packet_txbuf_found_station_for_first_entry(repeater_t *repeater, dmr_timeslot_t ts);
void data_packet_txbuf_remove_first_entry(void);
data_packet_txbuf_t *data_packet_txbuf_get_first_entry(void);

void data_packet_txbuf_reset_last_send_try_time(void);

void data_packet_txbuf_process(void);
void data_packet_txbuf_deinit(void);

#endif
