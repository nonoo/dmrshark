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
#include <libs/base/dmr.h>

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
	uint16_t crc; // 9 bit CRC
	flag_t received_ok;
	uint8_t data[24]; // See DMR AI spec. page. 73.
	uint8_t data_length;
} dmrpacket_data_block_t;

// n_DFragMax, see DMR AI spec. page 163.
#define DMRPACKET_MAX_FRAGMENTSIZE 1500

typedef struct {
	uint8_t bytes[DMRPACKET_MAX_FRAGMENTSIZE];
	uint16_t bytes_stored;
	uint8_t data_blocks_needed;
	uint32_t crc;
} dmrpacket_data_fragment_t;

typedef struct {
	uint8_t number_of_csbk_preambles_to_send;
	dmrpacket_data_type_t data_type;
	dmrpacket_data_header_t header;
	dmrpacket_data_fragment_t fragment;
} dmrpacket_data_packet_t;

char *dmrpacket_data_get_readable_data_type(dmrpacket_data_type_t data_type);

bptc_196_96_data_bits_t *dmrpacket_data_extract_and_repair_bptc_data(dmrpacket_payload_bits_t *packet_payload_bits);
dmrpacket_payload_info_bits_t *dmrpacket_data_bptc_deinterleave(dmrpacket_payload_info_bits_t *info_bits);
dmrpacket_payload_info_bits_t *dmrpacket_data_bptc_interleave(dmrpacket_payload_info_bits_t *deint_info_bits);

dmrpacket_data_block_bytes_t *dmrpacket_data_convert_binary_to_block_bytes(dmrpacket_data_binary_t *binary);
dmrpacket_data_block_bytes_t *dmrpacket_data_convert_payload_bptc_data_bits_to_block_bytes(bptc_196_96_data_bits_t *binary);

uint8_t dmrpacket_data_get_block_size(dmrpacket_data_type_t data_type, flag_t confirmed);
dmrpacket_data_block_t *dmrpacket_data_decode_block(dmrpacket_data_block_bytes_t *bytes, dmrpacket_data_type_t data_type, flag_t confirmed);
dmrpacket_data_fragment_t *dmrpacket_data_extract_fragment_from_blocks(dmrpacket_data_block_t *blocks, uint8_t blocks_count);
char *dmrpacket_data_convertmsg(uint8_t *in, uint16_t in_length, uint16_t *out_length, dmrpacket_data_header_dd_format_t src_dd_format, dmrpacket_data_header_dd_format_t dst_dd_format, uint8_t add_to_left);

dmrpacket_data_block_bytes_t *dmrpacket_data_construct_block_bytes(dmrpacket_data_block_t *data_block, flag_t confirmed);
dmrpacket_data_block_t *dmrpacket_data_construct_data_blocks(dmrpacket_data_fragment_t *fragment, dmrpacket_data_type_t data_type, flag_t confirmed);

void dmrpacket_data_get_needed_blocks_count(uint16_t data_bytes_count, dmrpacket_data_type_t data_type, flag_t confirmed, uint8_t *data_blocks_needed);
void dmrpacket_data_construct_fragment(uint8_t *data, uint16_t data_size, dmrpacket_data_type_t data_type, flag_t confirmed, dmrpacket_data_fragment_t *fragment);

struct iphdr *dmrpacket_construct_payload_motorola_tms_ack(dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, uint8_t rx_seqnum);
struct iphdr *dmrpacket_construct_payload_motorola_sms(char *msg, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, uint8_t tx_seqnum);

uint16_t dmrpacket_get_time_in_ms_needed_to_send(dmrpacket_data_packet_t *data_packet);

#endif
