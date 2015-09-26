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

#ifndef DMRPACKET_CSBK_H_
#define DMRPACKET_CSBK_H_

#include "dmrpacket-data.h"
#include "dmrpacket-types.h"

#include <libs/base/types.h>
#include <libs/base/dmr.h>

#define DMRPACKET_CSBKO_BS_OUTBOUND_ACTIVATION						0b111000
#define DMRPACKET_CSBKO_UNIT_TO_UNIT_VOICE_SERVICE_REQUEST			0b000100
#define DMRPACKET_CSBKO_UNIT_TO_UNIT_VOICE_SERVICE_ANSWER_RESPONSE	0b000101
#define DMRPACKET_CSBKO_NEGATIVE_ACKNOWLEDGE_RESPONSE				0b100110
#define DMRPACKET_CSBKO_PREAMBLE									0b111101
typedef uint8_t dmrpacket_csbko_t;

typedef struct {
	flag_t last_block;
	dmrpacket_csbko_t csbko;
	union {
		struct {
			uint8_t service_options;
		} unit_to_unit_voice_service_request;
		struct {
			uint8_t service_options;
			uint8_t answer_response;
		} unit_to_unit_voice_service_answer_response;
		struct {
			uint8_t source_type		: 1;
			uint8_t service_type	: 6;
			uint8_t reason_code;
		} negative_acknowledge_response;
		struct {
			uint8_t data_follows	: 1;
			uint8_t dst_is_group	: 1;
			uint8_t csbk_blocks_to_follow;
		} preamble;
	} data;
	dmr_id_t dst_id;
	dmr_id_t src_id;
} dmrpacket_csbk_t;

dmrpacket_csbk_t *dmrpacket_csbk_decode(bptc_196_96_data_bits_t *data_bits);
bptc_196_96_data_bits_t *dmrpacket_csbk_construct(dmrpacket_csbk_t *csbk);

#endif
