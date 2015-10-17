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

#ifndef DMR_H_
#define DMR_H_

#include "types.h"

#define DMR_CALL_TYPE_PRIVATE					0x00
#define DMR_CALL_TYPE_GROUP						0x01
typedef uint8_t dmr_call_type_t;

#define DMR_DATA_TYPE_UNKNOWN					0x00
#define DMR_DATA_TYPE_NORMAL_SMS				0x01
#define DMR_DATA_TYPE_MOTOROLA_TMS_SMS			0x02
typedef uint8_t dmr_data_type_t;

typedef uint8_t dmr_timeslot_t; // Note that the value for TS1 is 0, and for TS2 is 1.
typedef uint32_t dmr_id_t;
typedef uint8_t dmr_color_code_t;

char *dmr_get_readable_call_type(dmr_call_type_t call_type);
char *dmr_get_readable_data_type(dmr_data_type_t data_type);

#endif
