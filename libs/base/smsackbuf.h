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

#ifndef SMSACKBUF_H_
#define SMSACKBUF_H_

#include "dmr.h"

#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/comm/repeaters.h>

void smsackbuf_print(void);
void smsackbuf_add(dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, dmr_data_type_t datatype, char *msg);
void smsackbuf_ack_received(dmr_id_t ack_dstid, dmr_id_t ack_srcid, dmr_call_type_t ack_calltype, dmr_data_type_t acked_datatype);
void smsackbuf_call_ended(repeater_t *repeater, dmr_timeslot_t ts);

void smsackbuf_deinit(void);

#endif
