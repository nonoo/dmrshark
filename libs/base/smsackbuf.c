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

// This SMS ack buffer takes care of storing decoded messages until
// their calls are finished. If the message was unacked, it adds the
// message to the SMS retransmit buffer, otherwise it updloads it to
// the remote database log.

#include DEFAULTCONFIG

#include "smsackbuf.h"
#include "smsrtbuf.h"

#include <libs/daemon/console.h>
#include <libs/remotedb/remotedb.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

typedef struct smsackbuf_st {
	flag_t acked;
	time_t added_at;
	dmr_id_t dstid;
	dmr_id_t srcid;
	dmr_call_type_t calltype;
	dmr_data_type_t datatype;
	char msg[DMRPACKET_DATA_MAX_DECODED_DATA_SIZE];

	struct smsackbuf_st *next;
	struct smsackbuf_st *prev;
} smsackbuf_t;

static smsackbuf_t *smsackbuf_first_entry = NULL;

static void smsackbuf_print_entry(smsackbuf_t *entry) {
	char added_at_str[20];

	strftime(added_at_str, sizeof(added_at_str), "%F %T", localtime(&entry->added_at));
	console_log("  dst id: %u src id: %u calltype: %s datatype: %s added at: %s acked: %u data: %s\n",
		entry->dstid, entry->srcid, dmr_get_readable_call_type(entry->calltype), dmr_get_readable_data_type(entry->datatype),
		added_at_str, entry->acked, isprint(entry->msg[0]) ? entry->msg : "(not printable)");
}

void smsackbuf_print(void) {
	smsackbuf_t *entry = smsackbuf_first_entry;

	if (entry == NULL) {
		console_log("smsackbuf: empty\n");
		return;
	}
	console_log("smsackbuf:\n");
	while (entry) {
		smsackbuf_print_entry(entry);
		entry = entry->next;
	}
}

void smsackbuf_add(dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, dmr_data_type_t datatype, char *msg) {
	smsackbuf_t *new_entry;

	if (msg == NULL || datatype == DMR_DATA_TYPE_UNKNOWN || dstid == 0 || srcid == 0)
		return;

	new_entry = (smsackbuf_t *)calloc(1, sizeof(smsackbuf_t));
	if (new_entry == NULL) {
		console_log("  error: can't allocate memory for new data ack buffer entry\n");
		return;
	}

	strncpy(new_entry->msg, msg, sizeof(new_entry->msg));
	new_entry->added_at = time(NULL);
	new_entry->dstid = dstid;
	new_entry->srcid = srcid;
	new_entry->calltype = calltype;
	new_entry->datatype = datatype;

	console_log(LOGLEVEL_DATAQ "smsackbuf: adding new entry:\n");
	smsackbuf_print_entry(new_entry);

	if (smsackbuf_first_entry == NULL) {
		smsackbuf_first_entry = new_entry;
	} else {
		new_entry->next = smsackbuf_first_entry;
		smsackbuf_first_entry->prev = new_entry;
		smsackbuf_first_entry = new_entry;
	}
}

void smsackbuf_ack_received(dmr_id_t ack_dstid, dmr_id_t ack_srcid, dmr_call_type_t ack_calltype, dmr_data_type_t acked_datatype) {
	smsackbuf_t *entry = smsackbuf_first_entry;
	loglevel_t loglevel = console_get_loglevel();

	while (entry) {
		if (entry->dstid == ack_srcid && entry->srcid == ack_dstid && entry->calltype == ack_calltype && entry->datatype == acked_datatype) {
			entry->acked = 1;
			if (loglevel.flags.dataq) {
				console_log(LOGLEVEL_DATAQ "smsackbuf: got ack for entry:\n");
				smsackbuf_print_entry(entry);
			}
		}

		entry = entry->next;
	}
}

void smsackbuf_call_ended(repeater_t *repeater, dmr_timeslot_t ts, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype) {
	smsackbuf_t *entry = smsackbuf_first_entry;
	loglevel_t loglevel = console_get_loglevel();

	while (entry) {
		if (((entry->dstid == srcid && entry->srcid == dstid) || (entry->dstid == dstid && entry->srcid == srcid)) && entry->calltype == calltype) {
			if (loglevel.flags.dataq) {
				console_log(LOGLEVEL_DATAQ "smsackbuf: call end for entry:\n");
				smsackbuf_print_entry(entry);
			}

			if (entry->acked)
				remotedb_add_data_to_log(repeater, ts, entry->dstid, entry->srcid, entry->calltype, entry->datatype, entry->msg);
			else {
				if (entry->dstid != DMRSHARK_DEFAULT_DMR_ID && entry->srcid != DMRSHARK_DEFAULT_DMR_ID)
					smsrtbuf_add_decoded_message(repeater, ts, entry->datatype, entry->dstid, entry->srcid, entry->calltype, entry->msg);
			}

			if (entry->prev)
				entry->prev->next = entry->next;
			if (entry->next)
				entry->next->prev = entry->prev;
			if (entry == smsackbuf_first_entry)
				smsackbuf_first_entry = entry->next;
			free(entry);

			// Restarting the loop with the first entry.
			entry = smsackbuf_first_entry;
			continue;
		}
		entry = entry->next;
	}
}

void smsackbuf_deinit(void) {
	smsackbuf_t *next_entry;

	while (smsackbuf_first_entry != NULL) {
		next_entry = smsackbuf_first_entry->next;
		free(smsackbuf_first_entry);
		smsackbuf_first_entry = next_entry;
	}
}
