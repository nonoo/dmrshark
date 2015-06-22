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

#ifndef DMRPACKET_BPTC_H_
#define DMRPACKET_BPTC_H_

#include "dmrpacket.h"

typedef struct {
	flag_t bits[96];
} dmrpacket_payload_bptc_data_bits_t;

dmrpacket_payload_info_bits_t *dmrpacket_data_bptc_deinterleave(dmrpacket_payload_info_bits_t *info_bits);
void dmrpacket_data_bptc_check_and_repair(dmrpacket_payload_info_bits_t *deinterleaved_info_bits);
dmrpacket_payload_bptc_data_bits_t *dmrpacket_data_bptc_extractdata(dmrpacket_payload_info_bits_t *deinterleaved_info_bits);

#endif
