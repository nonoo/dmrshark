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

#ifndef DMRPACKET_DATA_34RATE_H_
#define DMRPACKET_DATA_34RATE_H_

#include "dmrpacket.h"
#include "dmrpacket-data.h"

typedef struct {
	dmrpacket_dibit_t dibits[98];
} dmrpacket_data_34rate_dibits_t;

typedef struct {
	uint8_t points[49];
} dmrpacket_data_34rate_constellationpoints_t;

typedef struct {
	dmrpacket_tribit_t tribits[48];
} dmrpacket_data_34rate_tribits_t;

dmrpacket_data_34rate_dibits_t *dmrpacket_data_34rate_extract_dibits(dmrpacket_payload_info_bits_t *info_bits);
dmrpacket_payload_info_bits_t *dmrpacket_data_34rate_construct_payload_info_bits(dmrpacket_data_34rate_dibits_t *dibits);

dmrpacket_data_34rate_dibits_t *dmrpacket_data_34rate_deinterleave_dibits(dmrpacket_data_34rate_dibits_t *dibits);
dmrpacket_data_34rate_dibits_t *dmrpacket_data_34rate_interleave_dibits(dmrpacket_data_34rate_dibits_t *dibits);

dmrpacket_data_34rate_constellationpoints_t *dmrpacket_data_34rate_getconstellationpoints(dmrpacket_data_34rate_dibits_t *deinterleaved_dibits);
dmrpacket_data_34rate_dibits_t *dmrpacket_data_34rate_construct_deinterleaved_dibits(dmrpacket_data_34rate_constellationpoints_t *constellationpoints);

dmrpacket_data_34rate_tribits_t *dmrpacket_data_34rate_extract_tribits(dmrpacket_data_34rate_constellationpoints_t *constellationpoints);
dmrpacket_data_34rate_constellationpoints_t *dmrpacket_data_34rate_construct_constellationpoints(dmrpacket_data_34rate_tribits_t *tribits);

dmrpacket_data_binary_t *dmrpacket_data_34rate_extract_binary(dmrpacket_data_34rate_tribits_t *tribits);
dmrpacket_data_34rate_tribits_t *dmrpacket_data_34rate_construct_tribits(dmrpacket_data_binary_t *binary);

#endif
