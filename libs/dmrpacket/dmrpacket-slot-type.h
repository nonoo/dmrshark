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

#ifndef DMRPACKET_SLOT_TYPE_H_
#define DMRPACKET_SLOT_TYPE_H_

#include "dmrpacket-types.h"
#include "dmrpacket-data.h"
#include "dmrpacket-sync.h"

#include <libs/base/dmr.h>

typedef struct {
	flag_t bits[10*2]; // See DMR AI spec. page 58.
} dmrpacket_slot_type_bits_t;

typedef struct {
	dmr_color_code_t cc;
	dmrpacket_data_type_t data_type;
} dmrpacket_slot_type_t;

dmrpacket_slot_type_bits_t *dmrpacket_slot_type_extract_bits(dmrpacket_payload_bits_t *payload_bits);
void dmrpacket_slot_type_insert_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_slot_type_bits_t *slot_type_bits);
dmrpacket_slot_type_bits_t *dmrpacket_slot_type_construct_bits(dmr_color_code_t cc, dmrpacket_data_type_t data_type);
dmrpacket_slot_type_t *dmrpacket_slot_type_decode(dmrpacket_slot_type_bits_t *slot_type_bits);

#endif
