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

#include <config/defaults.h>

#ifndef DMRPACKET_SYNC_H_
#define DMRPACKET_SYNC_H_

#include "dmrpacket-types.h"

typedef struct {
	flag_t bits[48];
} dmrpacket_sync_bits_t;

#define DMRPACKET_SYNC_PATTERN_TYPE_UNKNOWN							0x00
#define DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE				0x01
#define DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA					0x02
#define DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_VOICE				0x03
#define DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_DATA					0x04
#define DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_RC					0x05
#define DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS1				0x06
#define DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS1					0x07
#define DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS2				0x08
#define DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS2					0x09
typedef uint8_t dmrpacket_sync_pattern_type_t;

dmrpacket_sync_bits_t *dmrpacket_sync_extract_bits(dmrpacket_payload_bits_t *payload_bits);
void dmrpacket_sync_insert_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_sync_bits_t *sync_bits);
dmrpacket_sync_bits_t *dmrpacket_sync_construct_bits(dmrpacket_sync_pattern_type_t sync_pattern_type);

char *dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_pattern_type_t sync_pattern_type);
dmrpacket_sync_pattern_type_t dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_bits_t *sync_bits);

#endif
