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

#ifndef DMRPACKET_CONTROL_H_
#define DMRPACKET_CONTROL_H_

#include "dmrpacket.h"

#include <libs/base/types.h>
#include <libs/base/dmr.h>

typedef struct {
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
	uint32_t checksum; // Only 24 bits are used.
} dmrpacket_control_full_lc_t;

dmrpacket_control_full_lc_t *dmrpacket_control_decode_voice_lc_header(bptc_196_96_data_bits_t *data_bits);
dmrpacket_control_full_lc_t *dmrpacket_control_decode_terminator_with_lc(bptc_196_96_data_bits_t *data_bits);

#endif
