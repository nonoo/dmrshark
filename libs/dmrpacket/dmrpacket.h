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
#include <libs/base/dmr.h>

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

#define DMRPACKET_SYNC_TYPE_UNKNOWN						0x00
#define DMRPACKET_SYNC_TYPE_BS_SOURCED_VOICE			0x01
#define DMRPACKET_SYNC_TYPE_BS_SOURCED_DATA				0x02
#define DMRPACKET_SYNC_TYPE_MS_SOURCED_VOICE			0x03
#define DMRPACKET_SYNC_TYPE_MS_SOURCED_DATA				0x04
#define DMRPACKET_SYNC_TYPE_MS_SOURCED_RC				0x05
#define DMRPACKET_SYNC_TYPE_DIRECT_VOICE_TS1			0x06
#define DMRPACKET_SYNC_TYPE_DIRECT_DATA_TS1				0x07
#define DMRPACKET_SYNC_TYPE_DIRECT_VOICE_TS2			0x08
#define DMRPACKET_SYNC_TYPE_DIRECT_DATA_TS2				0x09
typedef uint8_t dmrpacket_sync_type_t;

#include "dmrpacket-data.h"
#include "dmrpacket-data-header.h"
#include "dmrpacket-data-34rate.h"
#include "dmrpacket-control.h"
#include "dmrpacket-emb.h"

typedef struct {
	dmr_color_code_t cc;
	dmrpacket_data_type_t data_type;
} dmrpacket_payload_slot_type_t;

dmrpacket_payload_info_bits_t *dmrpacket_extractinfobits(dmrpacket_payload_bits_t *payload_bits);
dmrpacket_payload_slot_type_bits_t *dmrpacket_extractslottypebits(dmrpacket_payload_bits_t *payload_bits);
dmrpacket_payload_sync_bits_t *dmrpacket_extractsyncbits(dmrpacket_payload_bits_t *payload_bits);

char *dmrpacket_get_readable_sync_type(dmrpacket_sync_type_t sync_type);
dmrpacket_sync_type_t dmrpacket_get_sync_type(dmrpacket_payload_sync_bits_t *sync_bits);

dmrpacket_payload_slot_type_t *dmrpacket_decode_slot_type(dmrpacket_payload_slot_type_bits_t *slot_type_bits);

#endif
