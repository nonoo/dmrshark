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

#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/daemon/console.h>
#include <libs/config/config.h>

#include <time.h>
#include <string.h>
#include <stdlib.h>

typedef struct smsrtbuf_st {
	smsrtbuf_sms_type_t sms_type;
	dmr_id_t dstid;
	dmr_id_t srcid;
	char msg[DMRPACKET_DATA_MAX_DECODED_SMS_SIZE];
	time_t last_added_at;

	struct smsrtbuf_st *next;
	struct smsrtbuf_st *prev;
} smsrtbuf_t;

static smsrtbuf_t *smsrtbuf_first_entry = NULL;
static smsrtbuf_t *smsrtbuf_last_entry = NULL;

static char *smsrtbuf_get_readable_sms_type(smsrtbuf_sms_type_t sms_type) {
	switch (sms_type) {
		case SMSRTBUF_SMS_TYPE_NORMAL: return "normal";
		case SMSRTBUF_SMS_TYPE_MOTOROLA_TMS: return "motorola tms";
		default: return "unknown";
	}
}

static void smsrtbuf_print_entry(smsrtbuf_t *entry) {
	int time_left;

	if (entry == NULL)
		return;

	time_left = config_get_smsretransmittimeoutinsec()-(time(NULL)-entry->last_added_at);
	if (time(NULL)-entry->last_added_at < 0)
		time_left = 0;
	console_log("  time left: %u type: %s dst: %u src: %u msg: %s\n", time_left,
		smsrtbuf_get_readable_sms_type(entry->sms_type), entry->dstid, entry->srcid, entry->msg);
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

static smsrtbuf_t *smsrtbuf_findentry(smsrtbuf_sms_type_t sms_type, dmr_id_t dstid, dmr_id_t srcid, char *msg) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;

	while (entry) {
		if (entry->sms_type == sms_type && entry->dstid == dstid && entry->srcid == srcid && strncmp(entry->msg, msg, DMRPACKET_DATA_MAX_DECODED_SMS_SIZE-1) == 0)
			return entry;

		entry = entry->next;
	}
	return NULL;
}

void smsrtbuf_add_decoded_message(smsrtbuf_sms_type_t sms_type, dmr_id_t dstid, dmr_id_t srcid, char *msg) {
	smsrtbuf_t *new_entry;
	loglevel_t loglevel;

	if (msg == NULL || sms_type == SMSRTBUF_SMS_TYPE_UNKNOWN || srcid == DMRSHARK_DEFAULT_DMR_ID || config_get_smsretransmittimeoutinsec() == 0)
		return;

	loglevel = console_get_loglevel();

	new_entry = smsrtbuf_findentry(sms_type, dstid, srcid, msg);
	if (new_entry != NULL) {
		// Entry already in the buffer.
		new_entry->last_added_at = time(NULL);
		if (loglevel.flags.dmr) {
			console_log(LOGLEVEL_DMR "smsrtbuf: updated entry:\n");
			smsrtbuf_print_entry(new_entry);
		}
		return;
	}

	new_entry = (smsrtbuf_t *)calloc(1, sizeof(smsrtbuf_t));
	new_entry->sms_type = sms_type;
	new_entry->dstid = dstid;
	new_entry->srcid = srcid;
	strncpy(new_entry->msg, msg, DMRPACKET_DATA_MAX_DECODED_SMS_SIZE-1);
	new_entry->last_added_at = time(NULL);

	if (loglevel.flags.dmr) {
		console_log(LOGLEVEL_DMR "smsrtbuf: added entry:\n");
		smsrtbuf_print_entry(new_entry);
	}

	if (smsrtbuf_first_entry == NULL)
		smsrtbuf_first_entry = smsrtbuf_last_entry = new_entry;
	else {
		smsrtbuf_last_entry->next = new_entry;
		new_entry->prev = smsrtbuf_last_entry;
		smsrtbuf_last_entry = new_entry;
	}
}

static void smsrtbuf_remove_entry(smsrtbuf_t *entry) {
	loglevel_t loglevel;

	if (entry == NULL)
		return;

	loglevel = console_get_loglevel();
	if (loglevel.flags.dmr) {
		console_log(LOGLEVEL_DMR "smsrtbuf: removing entry:\n");
		smsrtbuf_print_entry(entry);
	}

	if (entry->prev != NULL)
		entry->prev->next = entry->next;
	if (entry->next != NULL)
		entry->next->prev = entry->prev;

	if (smsrtbuf_first_entry == entry)
		smsrtbuf_first_entry = entry->next;
	if (smsrtbuf_last_entry == entry)
		smsrtbuf_last_entry = entry->prev;

	free(entry);
}

void smsrtbuf_process(void) {
	smsrtbuf_t *entry = smsrtbuf_first_entry;
	loglevel_t loglevel;
	char msg[DMRPACKET_DATA_MAX_DECODED_SMS_SIZE+50] = {0,};

	while (entry) {
		if (time(NULL)-entry->last_added_at > config_get_smsretransmittimeoutinsec()) {
			loglevel = console_get_loglevel();
			snprintf(msg, sizeof(msg), "%u: %s", entry->srcid, entry->msg); // TODO: add callsign
if (entry->srcid == 2161005 || entry->dstid == 2161005) { // TODO: remove
			switch (entry->sms_type) {
				case SMSRTBUF_SMS_TYPE_NORMAL:
					if (loglevel.flags.dmr) {
						console_log(LOGLEVEL_DMR "smsrtbuf: retransmitting as motorola tms sms:\n");
						smsrtbuf_print_entry(entry);
					}
					smstxbuf_add(NULL, 0, DMR_CALL_TYPE_PRIVATE, entry->dstid, DMRSHARK_DEFAULT_DMR_ID, 1, msg);
					break;
				case SMSRTBUF_SMS_TYPE_MOTOROLA_TMS:
					if (loglevel.flags.dmr) {
						console_log(LOGLEVEL_DMR "smsrtbuf: retransmitting as normal sms:\n");
						smsrtbuf_print_entry(entry);
					}
					smstxbuf_add(NULL, 0, DMR_CALL_TYPE_PRIVATE, entry->dstid, DMRSHARK_DEFAULT_DMR_ID, 0, msg);
					break;
				default:
					break;
			}
}
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
}
