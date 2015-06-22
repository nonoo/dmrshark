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

#ifndef DMRPACKET_H_
#define DMRPACKET_H_

#include <libs/base/types.h>

typedef int8_t dmrpacket_dibit_t;
typedef uint8_t dmrpacket_tribit_t;

typedef struct {
	flag_t bits[98+10+48+10+98]; // See DMR AI spec. page 85.
} dmrpacket_payload_bits_t;

typedef struct {
	flag_t bits[98*2];
} dmrpacket_payload_info_bits_t;

typedef struct {
	flag_t bits[10*2];
} dmrpacket_payload_slot_type_bits_t;

typedef struct {
	flag_t bits[48];
} dmrpacket_payload_sync_bits_t;

dmrpacket_payload_info_bits_t *dmrpacket_extractinfobits(dmrpacket_payload_bits_t *payload_bits);
dmrpacket_payload_slot_type_bits_t *dmrpacket_extractslottypebits(dmrpacket_payload_bits_t *payload_bits);
dmrpacket_payload_sync_bits_t *dmrpacket_extractsyncbits(dmrpacket_payload_bits_t *payload_bits);

#endif
