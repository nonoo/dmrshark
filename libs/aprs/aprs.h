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

void aprs_add_to_gpspos_queue(dmr_data_gpspos_t *gpspos, char *callsign, uint8_t ssid, char *repeater_callsign);

void aprs_init(void);
void aprs_deinit(void);

#endif
