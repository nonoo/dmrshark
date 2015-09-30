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

#ifndef TRELLIS_H_
#define TRELLIS_H_

#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/dmrpacket/dmrpacket-types.h>

typedef int8_t trellis_dibit_t;
typedef uint8_t trellis_tribit_t;

typedef struct {
	trellis_dibit_t dibits[98];
} trellis_dibits_t;

typedef struct {
	uint8_t points[49];
} trellis_constellationpoints_t;

typedef struct {
	trellis_tribit_t tribits[48];
} trellis_tribits_t;

trellis_dibits_t *trellis_extract_dibits(dmrpacket_payload_info_bits_t *info_bits);
dmrpacket_payload_info_bits_t *trellis_construct_payload_info_bits(trellis_dibits_t *dibits);

trellis_dibits_t *trellis_deinterleave_dibits(trellis_dibits_t *dibits);
trellis_dibits_t *trellis_interleave_dibits(trellis_dibits_t *dibits);

trellis_constellationpoints_t *trellis_getconstellationpoints(trellis_dibits_t *deinterleaved_dibits);
trellis_dibits_t *trellis_construct_deinterleaved_dibits(trellis_constellationpoints_t *constellationpoints);

trellis_tribits_t *trellis_extract_tribits(trellis_constellationpoints_t *constellationpoints);
trellis_constellationpoints_t *trellis_construct_constellationpoints(trellis_tribits_t *tribits);

dmrpacket_data_binary_t *trellis_extract_binary(trellis_tribits_t *tribits);
trellis_tribits_t *trellis_construct_tribits(dmrpacket_data_binary_t *binary);

#endif
