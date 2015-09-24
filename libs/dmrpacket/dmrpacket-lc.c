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

#include "dmrpacket-lc.h"

#include <libs/daemon/console.h>
#include <libs/coding/rs-12-9.h>
#include <libs/base/base.h>

#include <stdlib.h>
#include <string.h>

// See DMR services spec. page 52.
static dmrpacket_lc_t *dmrpacket_lc_decode(uint8_t bytes[9]) {
	static dmrpacket_lc_t lc;

	if (bytes == NULL)
		return NULL;

	if (bytes[0] & 0b10000000) {
		console_log(LOGLEVEL_DMRLC "    error: protect flag is not 0\n");
		return NULL;
	}

	switch (bytes[0] & 0b111111) {
		case 0b11: lc.call_type = DMR_CALL_TYPE_PRIVATE; break;
		case 0b00: lc.call_type = DMR_CALL_TYPE_GROUP; break;
		default: console_log(LOGLEVEL_DMRLC "    error: invalid flco\n"); return NULL;
	}
	console_log(LOGLEVEL_DMRLC "    call type from flco: %s\n", dmr_get_readable_call_type(lc.call_type));

	if (bytes[1] != 0) {
		console_log(LOGLEVEL_DMRLC "    error: feature set id is not 0\n");
		return NULL;
	}

	console_log(LOGLEVEL_DMRLC "    service options: 0x%.2x\n", bytes[2]);

	lc.dst_id = bytes[3] << 16 | bytes[4] << 8 | bytes[5];
	console_log(LOGLEVEL_DMRLC "    dst id: %u\n", lc.dst_id);
	lc.src_id = bytes[6] << 16 | bytes[7] << 8 | bytes[8];
	console_log(LOGLEVEL_DMRLC "    src id: %u\n", lc.src_id);
	return &lc;
}

static uint8_t *dmrpacket_lc_construct_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	static uint8_t bytes[12];

	memset(bytes, 0, sizeof(bytes));

	if (call_type == DMR_CALL_TYPE_PRIVATE)
		bytes[0] = 0b11;
	bytes[3] = (dst_id & 0xff0000) >> 16;
	bytes[4] = (dst_id & 0x00ff00) >> 8;
	bytes[5] = (dst_id & 0x0000ff);
	bytes[6] = (src_id & 0xff0000) >> 16;
	bytes[7] = (src_id & 0x00ff00) >> 8;
	bytes[8] = (src_id & 0x0000ff);

	return bytes;
}

dmrpacket_lc_t *dmrpacket_lc_decode_emb_signalling_lc(dmrpacket_emb_signalling_lc_bits_t *deinterleaved_emb_signalling_lc_bits) {
	uint8_t bytes[9];

	if (deinterleaved_emb_signalling_lc_bits == NULL)
		return NULL;

	if (!dmrpacket_emb_check_checksum(deinterleaved_emb_signalling_lc_bits))
		return NULL;

	base_bitstobytes(deinterleaved_emb_signalling_lc_bits->bits, 72, bytes, sizeof(bytes));

	return dmrpacket_lc_decode(bytes);
}

void dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_emb_signalling_lc_fragment_bits_t *emb_signalling_lc_fragment_bits) {
	if (payload_bits == NULL || emb_signalling_lc_fragment_bits == NULL)
		return;

	memcpy(payload_bits->bits+sizeof(dmrpacket_payload_voice_bits_t)/2+sizeof(dmrpacket_emb_bits_t)/2, emb_signalling_lc_fragment_bits->bits, sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t));
}

dmrpacket_emb_signalling_lc_bits_t *dmrpacket_lc_construct_emb_signalling_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	static dmrpacket_emb_signalling_lc_bits_t data_bits;
	uint8_t *bytes;
	uint16_t checksum = 0;
	uint8_t i;

	bytes = dmrpacket_lc_construct_lc(call_type, dst_id, src_id);

	for (i = 0; i < 9; i++)
		checksum += bytes[i];
	checksum %= 31; // See DMR AI spec. page. 142.

	data_bits.checksum[0] = (checksum >> 4) & 0x01;
	data_bits.checksum[1] = (checksum >> 3) & 0x01;
	data_bits.checksum[2] = (checksum >> 2) & 0x01;
	data_bits.checksum[3] = (checksum >> 1) & 0x01;
	data_bits.checksum[4] = checksum & 0x01;

	base_bytestobits(bytes, 9, data_bits.bits, sizeof(dmrpacket_emb_signalling_lc_bits_t));
	return &data_bits;
}

static dmrpacket_lc_t *dmrpacket_lc_decode_full_lc(uint8_t bytes[12]) {
	rs_12_9_poly_t syndrome;
	uint8_t errors_found;
	rs_12_9_correct_errors_result_t result = RS_12_9_CORRECT_ERRORS_RESULT_NO_ERRORS_FOUND;

	if (bytes == NULL)
		return NULL;

	rs_12_9_calc_syndrome((rs_12_9_codeword_t *)bytes, &syndrome);

	if (rs_12_9_check_syndrome(&syndrome) != 0)
		result = rs_12_9_correct_errors((rs_12_9_codeword_t *)bytes, &syndrome, &errors_found);

	console_log(LOGLEVEL_DMRLC "    reed-solomon checksum: 0x%.6x (", bytes[9] << 16 | bytes[10] << 8 | bytes[11]);
	switch (result) {
		default:
		case RS_12_9_CORRECT_ERRORS_RESULT_NO_ERRORS_FOUND:
			console_log(LOGLEVEL_DMRLC "ok)\n");
			return dmrpacket_lc_decode(bytes);
		case RS_12_9_CORRECT_ERRORS_RESULT_ERRORS_CORRECTED:
			console_log(LOGLEVEL_DMRLC "%u byte errors found and corrected)\n", errors_found);
			return dmrpacket_lc_decode(bytes);
		case RS_12_9_CORRECT_ERRORS_RESULT_ERRORS_CANT_BE_CORRECTED:
			console_log(LOGLEVEL_DMRLC "%u byte errors found - can't correct)\n", errors_found);
			return NULL;
	}
}

dmrpacket_lc_t *dmrpacket_lc_decode_voice_lc_header(bptc_196_96_data_bits_t *data_bits) {
	uint8_t bytes[12];

	if (data_bits == NULL)
		return NULL;

	console_log(LOGLEVEL_DMRLC "  decoding voice lc header:\n");

	base_bitstobytes(data_bits->bits, sizeof(bptc_196_96_data_bits_t), bytes, sizeof(bytes));

	// Applying CRC mask to the checksum. See DMR AI. spec. page 143.
	bytes[9] ^= 0x96;
	bytes[10] ^= 0x96;
	bytes[11] ^= 0x96;

	return dmrpacket_lc_decode_full_lc(bytes);
}

dmrpacket_lc_t *dmrpacket_lc_decode_terminator_with_lc(bptc_196_96_data_bits_t *data_bits) {
	uint8_t bytes[12];

	if (data_bits == NULL)
		return NULL;

	console_log(LOGLEVEL_DMRLC "  decoding terminator with lc:\n");

	base_bitstobytes(data_bits->bits, sizeof(bptc_196_96_data_bits_t), bytes, sizeof(bytes));

	// Applying CRC mask to the checksum. See DMR AI. spec. page 143.
	bytes[9] ^= 0x99;
	bytes[10] ^= 0x99;
	bytes[11] ^= 0x99;

	return dmrpacket_lc_decode_full_lc(bytes);
}

static uint8_t *dmrpacket_lc_construct_full_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	uint8_t *bytes;
	rs_12_9_checksum_t *checksum;

	bytes = dmrpacket_lc_construct_lc(call_type, dst_id, src_id);

	checksum = rs_12_9_calc_checksum((rs_12_9_codeword_t *)bytes);
	bytes[9] = checksum->bytes[0];
	bytes[10] = checksum->bytes[1];
	bytes[11] = checksum->bytes[2];

	return bytes;
}

bptc_196_96_data_bits_t *dmrpacket_lc_construct_voice_lc_header(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	static bptc_196_96_data_bits_t data_bits;
	uint8_t *bytes;

	bytes = dmrpacket_lc_construct_full_lc(call_type, dst_id, src_id);

	// Applying CRC mask to the checksum. See DMR AI. spec. page 143.
	bytes[9] ^= 0x96;
	bytes[10] ^= 0x96;
	bytes[11] ^= 0x96;

	base_bytestobits(bytes, 12, data_bits.bits, sizeof(bptc_196_96_data_bits_t));

	return &data_bits;
}

bptc_196_96_data_bits_t *dmrpacket_lc_construct_terminator_with_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id) {
	static bptc_196_96_data_bits_t data_bits;
	uint8_t *bytes;

	bytes = dmrpacket_lc_construct_full_lc(call_type, dst_id, src_id);

	// Applying CRC mask to the checksum. See DMR AI. spec. page 143.
	bytes[9] ^= 0x99;
	bytes[10] ^= 0x99;
	bytes[11] ^= 0x99;

	base_bytestobits(bytes, 12, data_bits.bits, sizeof(bptc_196_96_data_bits_t));

	return &data_bits;
}
