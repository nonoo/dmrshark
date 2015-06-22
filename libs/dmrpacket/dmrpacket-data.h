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

#ifndef DMRPACKET_DATA_H_
#define DMRPACKET_DATA_H_

#include "dmrpacket-data-header.h"

#include <libs/base/types.h>

#include <iconv.h>
#include <errno.h>

#define DMRPACKET_DATA_TYPE_PI_HEADER					0b0000
#define DMRPACKET_DATA_TYPE_VOICE_LC_HEADER				0b0001
#define DMRPACKET_DATA_TYPE_TERMINATOR_WITH_LC			0b0010
#define DMRPACKET_DATA_TYPE_CSBK						0b0011
#define DMRPACKET_DATA_TYPE_MBC_HEADER					0b0100
#define DMRPACKET_DATA_TYPE_MBC_CONTINUATION			0b0101
#define DMRPACKET_DATA_TYPE_DATA_HEADER					0b0110
#define DMRPACKET_DATA_TYPE_RATE_12_DATA				0b0111
#define DMRPACKET_DATA_TYPE_RATE_34_DATA				0b1000
#define DMRPACKET_DATA_TYPE_IDLE						0b1001
#define DMRPACKET_DATA_TYPE_RATE_1_DATA					0b1010
typedef uint8_t dmrpacket_data_type_t;

typedef struct {
	flag_t bits[216];
} dmrpacket_data_binary_t;

typedef struct {
	uint8_t bytes[27];
} dmrpacket_data_block_bytes_t;

typedef struct {
	uint8_t serialnr;
	uint16_t crc;
	uint8_t data[24]; // See DMR AI spec. page. 73.
	uint8_t data_length;
} dmrpacket_data_block_t;

// n_DFragMax, see DMR AI spec. page 163.
#define DMRPACKET_MAX_FRAGMENTSIZE 1500

typedef struct {
	uint8_t bytes[DMRPACKET_MAX_FRAGMENTSIZE];
	uint16_t bytes_stored;
} dmrpacket_data_fragment_t;

dmrpacket_data_block_bytes_t *dmrpacket_data_convert_binary_to_block_bytes(dmrpacket_data_binary_t *binary);
dmrpacket_data_block_bytes_t *dmrpacket_data_convert_payload_data_bits_to_block_bytes(dmrpacket_payload_data_bits_t *binary);

dmrpacket_data_block_t *dmrpacket_data_decode_block(dmrpacket_data_block_bytes_t *bytes, dmrpacket_data_type_t data_type, flag_t confirmed);
dmrpacket_data_fragment_t *dmrpacket_data_extract_fragment_from_blocks(dmrpacket_data_block_t *blocks, uint8_t blocks_count);
char *dmrpacket_data_convertmsg(dmrpacket_data_fragment_t *fragment, dmrpacket_data_header_dd_format_t dd_format);

#endif
