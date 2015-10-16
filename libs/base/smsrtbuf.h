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

#ifndef SMSRTBUF_H_
#define SMSRTBUF_H_

#include "dmr.h"

#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/comm/repeaters.h>

#include <time.h>

typedef struct smsrtbuf_st {
	dmr_sms_type_t orig_sms_type;
	repeater_t *repeater;
	dmr_timeslot_t ts;
	dmr_id_t dstid;
	dmr_id_t srcid;
	dmr_call_type_t calltype;
	char orig_msg[DMRPACKET_DATA_MAX_DECODED_SMS_SIZE];
	char sent_msg[DMRPACKET_DATA_MAX_DECODED_SMS_SIZE+50];
	time_t last_added_at;
	flag_t currently_sending;

	struct smsrtbuf_st *next;
	struct smsrtbuf_st *prev;
} smsrtbuf_t;

void smsrtbuf_print(void);

smsrtbuf_t *smsrtbuf_find_entry(dmr_id_t dstid, char *msg);
void smsrtbuf_add_decoded_message(repeater_t *repeater, dmr_timeslot_t ts, dmr_sms_type_t sms_type, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, char *msg);
void smsrtbuf_got_ack(dmr_id_t dstid, dmr_call_type_t calltype);
void smsrtbuf_got_tms_ack(dmr_id_t dstid, dmr_call_type_t calltype);
void smsrtbuf_entry_sent_successfully(smsrtbuf_t *entry);
void smsrtbuf_entry_send_unsuccessful(smsrtbuf_t *entry);

void smsrtbuf_process(void);
void smsrtbuf_deinit(void);

#endif
