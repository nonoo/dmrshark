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

#include DEFAULTCONFIG

#include "dmrpacket-csbk.h"

#include <libs/base/base.h>
#include <libs/coding/crc.h>
#include <libs/daemon/console.h>

#include <stdlib.h>
#include <string.h>

static char *dmrpacket_csbk_get_readable_csbko(dmrpacket_csbko_t csbko) {
	switch (csbko) {
		case DMRPACKET_CSBKO_BS_OUTBOUND_ACTIVATION: return "bs outbound activation";
		case DMRPACKET_CSBKO_UNIT_TO_UNIT_VOICE_SERVICE_REQUEST: return "unit to unit voice service request";
		case DMRPACKET_CSBKO_UNIT_TO_UNIT_VOICE_SERVICE_ANSWER_RESPONSE: return "unit to unit voice service answer response";
		case DMRPACKET_CSBKO_NEGATIVE_ACKNOWLEDGE_RESPONSE: return "negative acknowledge response";
		case DMRPACKET_CSBKO_PREAMBLE: return "preamble";
		default: return "unknown";
	}
}

// See DMR AI. spec. page 67. and DMR services spec. page 53.
dmrpacket_csbk_t *dmrpacket_csbk_decode(bptc_196_96_data_bits_t *data_bits) {
	static dmrpacket_csbk_t csbk;
	uint8_t i;
	uint16_t calculated_crc = 0;
	uint16_t crc;
	uint8_t bytes[12];

	if (data_bits == NULL)
		return NULL;

	console_log(LOGLEVEL_DMRLC "  decoding csbk:\n");

	base_bitstobytes(data_bits->bits, sizeof(bptc_196_96_data_bits_t), bytes, sizeof(bytes));

	for (i = 0; i < 10; i++)
		crc_calc_crc16_ccitt(&calculated_crc, bytes[i]);
	crc_calc_crc16_ccitt_finish(&calculated_crc);

	// Inverting according to the inversion polynomial.
	calculated_crc = ~calculated_crc;
	// Applying CRC mask, see DMR AI spec. page 143.
	calculated_crc ^= 0xa5a5;

	crc = bytes[10] << 8 | bytes[11];
	console_log(LOGLEVEL_DMRLC "    crc: %.4x calculated: %.4x (%s)\n", crc, calculated_crc, calculated_crc != crc ? "error" : "ok");
	if (calculated_crc != crc)
		return NULL;

	if (bytes[0] & 0b01000000) {
		console_log(LOGLEVEL_DMRLC "    error: protect flag is not 0\n");
		return NULL;
	}
	if (bytes[1] != 0) {
		console_log(LOGLEVEL_DMRLC "    error: feature set id is not 0\n");
		return NULL;
	}

	csbk.last_block = (bytes[0] & 0b10000000) > 0;
	console_log(LOGLEVEL_DMRLC "    last block: %u\n", csbk.last_block);
	csbk.dst_id = bytes[4] << 16 | bytes[5] << 8 | bytes[6];
	console_log(LOGLEVEL_DMRLC "    dst id: %u\n", csbk.dst_id);
	csbk.src_id = bytes[7] << 16 | bytes[8] << 8 | bytes[9];
	console_log(LOGLEVEL_DMRLC "    src id: %u\n", csbk.src_id);

	csbk.csbko = bytes[0] & 0b111111;
	console_log(LOGLEVEL_DMRLC "    csbko: %s (%.2x)\n", dmrpacket_csbk_get_readable_csbko(csbk.csbko), csbk.csbko);
	switch (csbk.csbko) {
		case DMRPACKET_CSBKO_BS_OUTBOUND_ACTIVATION: // No important params to parse.
			break;
		case DMRPACKET_CSBKO_UNIT_TO_UNIT_VOICE_SERVICE_REQUEST:
			csbk.data.unit_to_unit_voice_service_request.service_options = bytes[3];
			console_log(LOGLEVEL_DMRLC "      service options: 0x%.2x\n", csbk.data.unit_to_unit_voice_service_request.service_options);
			break;
		case DMRPACKET_CSBKO_UNIT_TO_UNIT_VOICE_SERVICE_ANSWER_RESPONSE:
			csbk.data.unit_to_unit_voice_service_answer_response.service_options = bytes[3];
			console_log(LOGLEVEL_DMRLC "      service options: 0x%.2x\n", csbk.data.unit_to_unit_voice_service_answer_response.service_options);
			csbk.data.unit_to_unit_voice_service_answer_response.answer_response = bytes[4];
			console_log(LOGLEVEL_DMRLC "      answer response: 0x%.2x\n", csbk.data.unit_to_unit_voice_service_answer_response.answer_response);
			break;
		case DMRPACKET_CSBKO_NEGATIVE_ACKNOWLEDGE_RESPONSE:
			csbk.data.negative_acknowledge_response.source_type = ((bytes[3] & 0b01000000) > 0);
			console_log(LOGLEVEL_DMRLC "      source type: %u", csbk.data.negative_acknowledge_response.source_type);
			csbk.data.negative_acknowledge_response.service_type = bytes[3] & 0b111111;
			console_log(LOGLEVEL_DMRLC "      service type: 0x%.2x\n", csbk.data.negative_acknowledge_response.service_type);
			csbk.data.negative_acknowledge_response.reason_code = bytes[4];
			console_log(LOGLEVEL_DMRLC "      reason code: 0x%.2x\n", csbk.data.negative_acknowledge_response.reason_code);
			break;
		case DMRPACKET_CSBKO_PREAMBLE:
			csbk.data.preamble.data_follows = ((bytes[3] & 0b10000000) > 0);
			console_log(LOGLEVEL_DMRLC "      data follows: %u\n", csbk.data.preamble.data_follows);
			csbk.data.preamble.dst_is_group = ((bytes[3] & 0b01000000) > 0);
			console_log(LOGLEVEL_DMRLC "      dst is group: %u\n", csbk.data.preamble.dst_is_group);
			csbk.data.preamble.csbk_blocks_to_follow = bytes[4];
			console_log(LOGLEVEL_DMRLC "      blocks to follow: %u\n", csbk.data.preamble.csbk_blocks_to_follow);
			break;
		default:
			console_log(LOGLEVEL_DMRLC "      unknown csbko\n");
			return NULL;
	}

	return &csbk;
}
