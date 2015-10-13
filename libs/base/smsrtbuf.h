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

#define SMSRTBUF_SMS_TYPE_UNKNOWN		0
#define SMSRTBUF_SMS_TYPE_NORMAL		1
#define SMSRTBUF_SMS_TYPE_MOTOROLA_TMS	2
typedef uint8_t smsrtbuf_sms_type_t;

void smsrtbuf_print(void);

void smsrtbuf_add_decoded_message(smsrtbuf_sms_type_t sms_type, dmr_id_t dstid, dmr_id_t srcid, char *msg);

void smsrtbuf_process(void);
void smsrtbuf_deinit(void);

#endif
