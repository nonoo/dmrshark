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

#include "data-packet-txbuf.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/comm/repeaters.h>
#include <libs/config/config.h>

#include <stdlib.h>
#include <string.h>
#include <math.h>

// All data packets which need an ack should be put into the data packet
// TX buffer, which is a FIFO. Only one item gets sent at a time and
// retried periodically until an ack is received.

static data_packet_txbuf_t *data_packet_txbuf_first_entry = NULL;
static data_packet_txbuf_t *data_packet_txbuf_last_entry = NULL;

static time_t data_packet_txbuf_last_send_try_at = 0;

void data_packet_txbuf_print_entry(data_packet_txbuf_t *entry) {
	char added_at_str[20];

	strftime(added_at_str, sizeof(added_at_str), "%F %T", gmtime(&entry->added_at));
	console_log("  bcast: %u, dst id: %u src id: %u type: %s added at: %s send tries: %u bytes stored: %u crc: %.8x\n",
		entry->broadcast_to_all_repeaters, entry->data_packet.header.common.dst_llid, entry->data_packet.header.common.src_llid,
		dmr_get_readable_call_type(entry->data_packet.header.common.dst_is_a_group ? DMR_CALL_TYPE_GROUP : DMR_CALL_TYPE_PRIVATE),
		added_at_str, entry->send_tries, entry->data_packet.fragment.bytes_stored, entry->data_packet.fragment.crc);
}

void data_packet_txbuf_print(void) {
	data_packet_txbuf_t *entry = data_packet_txbuf_first_entry;

	if (entry == NULL) {
		console_log("data packet txbuf: empty\n");
		return;
	}
	console_log("data packet txbuf:\n");
	while (entry) {
		data_packet_txbuf_print_entry(entry);
		entry = entry->next;
	}
}

void data_packet_txbuf_add(flag_t broadcast_to_all_repeaters, repeater_t *repeater, dmr_timeslot_t ts, dmrpacket_data_packet_t *data_packet) {
	data_packet_txbuf_t *new_data_packet_txbuf_entry;

	if (data_packet == NULL)
		return;

	new_data_packet_txbuf_entry = (data_packet_txbuf_t *)calloc(1, sizeof(data_packet_txbuf_t));
	if (new_data_packet_txbuf_entry == NULL) {
		console_log("  error: can't allocate memory for new data packet tx buffer entry\n");
		return;
	}

	memcpy(&new_data_packet_txbuf_entry->data_packet, data_packet, sizeof(dmrpacket_data_packet_t));
	new_data_packet_txbuf_entry->added_at = time(NULL);
	new_data_packet_txbuf_entry->broadcast_to_all_repeaters = broadcast_to_all_repeaters;
	new_data_packet_txbuf_entry->repeater = repeater;
	new_data_packet_txbuf_entry->ts = ts;

	console_log(LOGLEVEL_DATAQ "data packet txbuf: adding new entry:\n");
	data_packet_txbuf_print_entry(new_data_packet_txbuf_entry);

	if (data_packet_txbuf_last_entry == NULL) {
		data_packet_txbuf_last_entry = data_packet_txbuf_first_entry = new_data_packet_txbuf_entry;
	} else {
		// Putting the new entry to the end of the linked list.
		data_packet_txbuf_last_entry->next = new_data_packet_txbuf_entry;
		data_packet_txbuf_last_entry = new_data_packet_txbuf_entry;
	}
	daemon_poll_setmaxtimeout(0);
}

void data_packet_txbuf_found_station_for_first_entry(repeater_t *repeater, dmr_timeslot_t ts) {
	if (data_packet_txbuf_first_entry == NULL)
		return;

	data_packet_txbuf_first_entry->repeater = repeater;
	data_packet_txbuf_first_entry->ts = ts;
	data_packet_txbuf_first_entry->broadcast_to_all_repeaters = 0;
}

void data_packet_txbuf_remove_first_entry(void) {
	data_packet_txbuf_t *nextentry;

	if (data_packet_txbuf_first_entry == NULL)
		return;

	nextentry = data_packet_txbuf_first_entry->next;
	free(data_packet_txbuf_first_entry);
	data_packet_txbuf_first_entry = nextentry;
	if (data_packet_txbuf_first_entry == NULL)
		data_packet_txbuf_last_entry = NULL;
	else
		daemon_poll_setmaxtimeout(0);
}

data_packet_txbuf_t *data_packet_txbuf_get_first_entry(void) {
	return data_packet_txbuf_first_entry;
}

void data_packet_txbuf_reset_last_send_try_time(void) {
	data_packet_txbuf_last_send_try_at = time(NULL);
}

void data_packet_txbuf_process(void) {
	uint16_t timeout;

	if (data_packet_txbuf_first_entry == NULL)
		return;

	if (repeaters_is_there_a_call_not_for_us_or_by_us(data_packet_txbuf_first_entry->repeater, data_packet_txbuf_first_entry->ts))
		return;

	timeout = config_get_mindatapacketsendretryintervalinsec()+ceil(dmrpacket_data_get_time_in_ms_needed_to_send(&data_packet_txbuf_first_entry->data_packet)/1000.0);
	if (time(NULL)-data_packet_txbuf_last_send_try_at < timeout) {
		daemon_poll_setmaxtimeout(timeout-(time(NULL)-data_packet_txbuf_last_send_try_at));
		return;
	}

	if (data_packet_txbuf_first_entry->send_tries >= config_get_datapacketsendmaxretrycount()) {
		console_log(LOGLEVEL_DATAQ "data packet txbuf: all tries of sending the first entry has failed, removing:\n");
		data_packet_txbuf_print_entry(data_packet_txbuf_first_entry);
		data_packet_txbuf_remove_first_entry();
		if (data_packet_txbuf_first_entry == NULL)
			return;
	}

	data_packet_txbuf_first_entry->selective_ack_tries = 0;
	console_log(LOGLEVEL_DATAQ "data packet txbuf: sending entry:\n");
	data_packet_txbuf_print_entry(data_packet_txbuf_first_entry);

	if (data_packet_txbuf_first_entry->broadcast_to_all_repeaters)
		repeaters_send_broadcast_data_packet(&data_packet_txbuf_first_entry->data_packet);
	else
		repeaters_send_data_packet(data_packet_txbuf_first_entry->repeater, data_packet_txbuf_first_entry->ts, NULL, 0, &data_packet_txbuf_first_entry->data_packet);

	if (data_packet_txbuf_first_entry->data_packet.header.common.dst_is_a_group || // Group messages are unconfirmed, so we send them only once.
		!data_packet_txbuf_first_entry->data_packet.header.common.response_requested) {
			data_packet_txbuf_remove_first_entry();
	} else
		data_packet_txbuf_first_entry->send_tries++;
	data_packet_txbuf_reset_last_send_try_time();
	daemon_poll_setmaxtimeout(0);
}

void data_packet_txbuf_deinit(void) {
	data_packet_txbuf_t *next_entry;

	while (data_packet_txbuf_first_entry != NULL) {
		next_entry = data_packet_txbuf_first_entry->next;
		free(data_packet_txbuf_first_entry);
		data_packet_txbuf_first_entry = next_entry;
	}
	data_packet_txbuf_last_entry = NULL;
}
