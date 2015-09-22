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

#include "dmrpacket-types.h"

#include <libs/base/dmr.h>

dmrpacket_payload_info_bits_t *dmrpacket_extract_info_bits(dmrpacket_payload_bits_t *payload_bits);
void dmrpacket_insert_info_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_payload_info_bits_t *info_bits);

dmrpacket_payload_voice_bits_t *dmrpacket_extract_voice_bits(dmrpacket_payload_bits_t *payload_bits);
void dmrpacket_insert_voice_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_payload_voice_bits_t *voice_bits);

#endif
