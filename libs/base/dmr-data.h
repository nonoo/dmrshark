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

#ifndef DMR_DATA_H_
#define DMR_DATA_H_

#include <libs/comm/repeaters.h>

#include "dmr.h"

typedef struct  {
	double latitude;
	char latitude_ch;
	double longitude;
	char longitude_ch;
	uint16_t speed; // In knots/h
	uint16_t heading;
	flag_t speed_valid		: 1;
	flag_t heading_valid	: 1;
} dmr_data_gpspos_t;

void dmr_data_send_selective_ack(repeater_t *repeater, dmr_id_t dstid, dmr_id_t srcid, dmr_timeslot_t ts,
	flag_t *selective_blocks, uint8_t selective_blocks_size, dmrpacket_data_header_sap_t service_access_point);
void dmr_data_send_motorola_tms_sms(flag_t broadcast_to_all_repeaters, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, char *msg);
void dmr_data_send_motorola_tms_ack(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, uint8_t rx_seqnum);
void dmr_data_send_ack(repeater_t *repeater, dmr_id_t dstid, dmr_id_t srcid, dmr_timeslot_t ts, dmrpacket_data_header_sap_t sap);
void dmr_data_send_sms(flag_t broadcast_to_all_repeaters, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, char *msg);

void dmr_data_send_sms_rms_volume_if_needed(repeater_t *repeater, dmr_timeslot_t ts);

dmr_data_gpspos_t *dmr_data_decode_hytera_gps_triggered(uint8_t *message_data, uint16_t message_data_length);
dmr_data_gpspos_t *dmr_data_decode_hytera_gps_button(uint8_t *message_data, uint16_t message_data_length);

char *dmr_data_get_gps_string_latitude(double latitude);
char *dmr_data_get_gps_string_longitude(double longitude);
char *dmr_data_get_gps_string(dmr_data_gpspos_t *gpspos);

#endif
