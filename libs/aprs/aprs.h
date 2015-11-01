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

#ifndef APRS_H_
#define APRS_H_

#include <libs/base/dmr-data.h>

// See http://www.aprs.org/txt/messages.txt
#define APRS_MAX_MESSAGE_LENGTH 67

typedef struct {
	char dst_callsign[10];
	char src_callsign[10];
	char msg[APRS_MAX_MESSAGE_LENGTH];
	char ackpart[6];
} aprs_msg_t;

void aprs_add_to_queue_msg(char *dst_callsign, char *src_callsign, char *msg, char *repeater_callsign);
void aprs_add_to_queue_gpspos(dmr_data_gpspos_t *gpspos, char *callsign, uint8_t ssid, char *repeater_callsign);

void aprs_init(void);
void aprs_deinit(void);

#endif
