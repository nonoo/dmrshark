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

#include "smsrtbuf.h"
#include "smstxbuf.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>
#include <libs/remotedb/userdb.h>

#include <string.h>
#include <stdlib.h>

static smsrtbuf_t *smsrtbuf_first_entry = NULL;

static void smsrtbuf_print_entry(smsrtbuf_t *entry) {
	time_t time_left;

	if (entry == NULL)
		return;

	time_left = config_get_smsretransmittimeoutinsec()-(time(NULL)-entry->last_added_at);
	if (time_left < 0)
		time_left = 0;
	console_log("  time left: %u orig type: %s dst: %u src: %u msg: %s\n", time_left,
		dmr_get_readable_data_type(entry->orig_data_type), entry->dstid, entry->srcid, entry->orig_msg);
}

void smsrtbuf_print(void) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;

	if (entry == NULL) {
		console_log("smsrtbuf: empty\n");
		return;
	}

	console_log("smsrtbuf:\n");
	while (entry) {
		smsrtbuf_print_entry(entry);
		entry = entry->next;
	}
}

smsrtbuf_t *smsrtbuf_find_entry(dmr_id_t dstid, char *msg) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;

	if (msg == NULL)
		return NULL;

	while (entry) {
		if (entry->dstid == dstid && (strncmp(entry->sent_msg, msg, DMRPACKET_DATA_MAX_DECODED_DATA_SIZE) == 0 || strncmp(entry->orig_msg, msg, DMRPACKET_DATA_MAX_DECODED_DATA_SIZE) == 0))
			return entry;

		entry = entry->next;
	}
	return NULL;
}

static smsrtbuf_t *smsrtbuf_find_entry_by_ack(dmr_id_t dstid, dmr_call_type_t calltype) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;

	while (entry) {
		if (entry->dstid == dstid && entry->calltype == calltype)
			return entry;

		entry = entry->next;
	}
	return NULL;
}

void smsrtbuf_add_decoded_message(repeater_t *repeater, dmr_timeslot_t ts, dmr_data_type_t sms_type, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, char *msg) {
	smsrtbuf_t *new_entry;
	smsrtbuf_t *last_entry;
	loglevel_t loglevel;

	if (repeater == NULL || msg == NULL || sms_type == DMR_DATA_TYPE_UNKNOWN || srcid == DMRSHARK_DEFAULT_DMR_ID || config_get_smsretransmittimeoutinsec() == 0)
		return;

	loglevel = console_get_loglevel();

	new_entry = smsrtbuf_find_entry(dstid, msg);
	if (new_entry != NULL) {
		// Entry already in the buffer.
		new_entry->last_added_at = time(NULL);
		if (loglevel.flags.dataq) {
			console_log(LOGLEVEL_DATAQ "smsrtbuf: updated entry:\n");
			smsrtbuf_print_entry(new_entry);
		}
		return;
	}

	new_entry = (smsrtbuf_t *)calloc(1, sizeof(smsrtbuf_t));
	new_entry->orig_data_type = sms_type;
	new_entry->dstid = dstid;
	new_entry->srcid = srcid;
	new_entry->calltype = calltype;
	new_entry->ts = ts;
	new_entry->repeater = repeater;
	strncpy(new_entry->orig_msg, msg, DMRPACKET_DATA_MAX_DECODED_DATA_SIZE-1);
	new_entry->last_added_at = time(NULL);

	if (loglevel.flags.dataq) {
		console_log(LOGLEVEL_DATAQ "smsrtbuf: added entry:\n");
		smsrtbuf_print_entry(new_entry);
	}

	if (smsrtbuf_first_entry == NULL)
		smsrtbuf_first_entry = new_entry;
	else {
		// Adding to the end of the linked list.
		last_entry = smsrtbuf_first_entry;
		while (last_entry->next)
			last_entry = last_entry->next;
		last_entry->next = new_entry;
		new_entry->prev = last_entry;
	}
}

static void smsrtbuf_remove_entry(smsrtbuf_t *entry) {
	loglevel_t loglevel;

	if (entry == NULL)
		return;

	loglevel = console_get_loglevel();
	if (loglevel.flags.dataq) {
		console_log(LOGLEVEL_DATAQ "smsrtbuf: removing entry:\n");
		smsrtbuf_print_entry(entry);
	}

	if (entry->prev != NULL)
		entry->prev->next = entry->next;
	if (entry->next != NULL)
		entry->next->prev = entry->prev;

	if (smsrtbuf_first_entry == entry)
		smsrtbuf_first_entry = entry->next;

	free(entry);
}

void smsrtbuf_got_ack(dmr_id_t dstid, dmr_call_type_t calltype) {
	smsrtbuf_t *entry;

	entry = smsrtbuf_find_entry_by_ack(dstid, calltype);
	if (entry) {
		if (entry->orig_data_type == DMR_DATA_TYPE_NORMAL_SMS) {
			console_log(LOGLEVEL_DATAQ "smsrtbuf: entry found but it's not a normal sms so waiting for the tms ack\n");
			return;
		}
		smsrtbuf_remove_entry(entry);
	}
}

void smsrtbuf_got_tms_ack(dmr_id_t dstid, dmr_call_type_t calltype) {
	smsrtbuf_t *entry;

	entry = smsrtbuf_find_entry_by_ack(dstid, calltype);
	if (entry) {
		if (entry->orig_data_type == DMR_DATA_TYPE_MOTOROLA_TMS_SMS) {
			console_log(LOGLEVEL_DATAQ "smsrtbuf: entry found but it's not a motorola tms sms so waiting for the tms ack\n");
			return;
		}
		smsrtbuf_remove_entry(entry);
	}
}

void smsrtbuf_entry_sent_successfully(smsrtbuf_t *entry) {
	char msg[DMRPACKET_DATA_MAX_DECODED_DATA_SIZE+50] = {0,};
	loglevel_t loglevel;

	if (entry == NULL)
		return;

	loglevel = console_get_loglevel();
	if (loglevel.flags.dataq) {
		console_log(LOGLEVEL_DATAQ "smsrtbuf: entry sent successfully:\n");
		smsrtbuf_print_entry(entry);
	}
	snprintf(msg, sizeof(msg), "Retransmitted SMS to %s: %s", userdb_get_display_str_for_id(entry->dstid), entry->orig_msg);
	smstxbuf_add(entry->repeater, entry->ts, DMR_CALL_TYPE_PRIVATE, entry->srcid, entry->orig_data_type, msg, 0);

	smsrtbuf_remove_entry(entry);
}

void smsrtbuf_entry_send_unsuccessful(smsrtbuf_t *entry) {
	char msg[DMRPACKET_DATA_MAX_DECODED_DATA_SIZE+50] = {0,};
	loglevel_t loglevel;

	if (entry == NULL)
		return;

	loglevel = console_get_loglevel();
	if (loglevel.flags.dataq) {
		console_log(LOGLEVEL_DATAQ "smsrtbuf: failed to retransmit entry:\n");
		smsrtbuf_print_entry(entry);
	}
	snprintf(msg, sizeof(msg), "Failed retransmitting SMS to %s: %s", userdb_get_display_str_for_id(entry->dstid), entry->orig_msg);

	smstxbuf_add(entry->repeater, entry->ts, DMR_CALL_TYPE_PRIVATE, entry->srcid, entry->orig_data_type, msg, 0);
	smsrtbuf_remove_entry(entry);
}

void smsrtbuf_process(void) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;
	loglevel_t loglevel;

	while (entry) {
		if (!entry->currently_sending && time(NULL)-entry->last_added_at > config_get_smsretransmittimeoutinsec()) {
			loglevel = console_get_loglevel();
			snprintf(entry->sent_msg, sizeof(entry->sent_msg), "%s: %s", userdb_get_display_str_for_id(entry->srcid), entry->orig_msg);

			switch (entry->orig_data_type) {
				case DMR_DATA_TYPE_NORMAL_SMS:
					if (loglevel.flags.dataq) {
						console_log(LOGLEVEL_DATAQ "smsrtbuf: retransmitting as motorola tms sms:\n");
						smsrtbuf_print_entry(entry);
					}
					smstxbuf_add(NULL, 0, entry->calltype, entry->dstid, DMR_DATA_TYPE_MOTOROLA_TMS_SMS, entry->sent_msg, 0);
					entry->currently_sending = 1;
					break;
				case DMR_DATA_TYPE_MOTOROLA_TMS_SMS:
					if (loglevel.flags.dataq) {
						console_log(LOGLEVEL_DATAQ "smsrtbuf: retransmitting as normal sms:\n");
						smsrtbuf_print_entry(entry);
					}
					smstxbuf_add(NULL, 0, entry->calltype, entry->dstid, DMR_DATA_TYPE_NORMAL_SMS, entry->sent_msg, 0);
					entry->currently_sending = 1;
					break;
				default:
					smsrtbuf_remove_entry(entry);
					break;
			}

			if (entry->calltype == DMR_CALL_TYPE_GROUP) {
				smsrtbuf_entry_sent_successfully(entry);
				break;
			}
		}

		if (entry->currently_sending && time(NULL)-entry->last_added_at > 600) { // Cleanup
			smsrtbuf_remove_entry(entry);
			break;
		}

		entry = entry->next;
	}
}

void smsrtbuf_deinit(void) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;
	smsrtbuf_t *next_entry;

	while (entry) {
		next_entry = entry->next;
		smsrtbuf_remove_entry(entry);
		entry = next_entry;
	}
	smsrtbuf_first_entry = NULL;
}
