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

#include "dmrpacket-control.h"

#include <libs/base/base.h>
#include <libs/coding/rs-12-9.h>
#include <libs/daemon/console.h>

#include <stdlib.h>

dmrpacket_control_full_lc_t *dmrpacket_control_decode_full_lc(uint8_t bytes[12]) {
	static dmrpacket_control_full_lc_t full_lc;
	rs_12_9_poly_t syndrome;
	uint8_t errors_found;
	rs_12_9_correct_errors_result_t result = RS_12_9_CORRECT_ERRORS_RESULT_NO_ERRORS_FOUND;

	if (bytes == NULL)
		return NULL;

	rs_12_9_calc_syndrome((rs_12_9_codeword_t *)bytes, &syndrome);

	if (rs_12_9_check_syndrome(&syndrome) != 0)
		result = rs_12_9_correct_errors((rs_12_9_codeword_t *)bytes, &syndrome, &errors_found);

	if (bytes[0] & 0b1100000)
		full_lc.call_type = DMR_CALL_TYPE_PRIVATE;
	else
		full_lc.call_type = DMR_CALL_TYPE_GROUP;

	console_log(LOGLEVEL_COMM_DMR "    call type: %s\n", dmr_get_readable_call_type(full_lc.call_type));

	full_lc.dst_id = bytes[3] << 16 | bytes[4] << 8 | bytes[5];
	console_log(LOGLEVEL_COMM_DMR "    dst id: %u\n", full_lc.dst_id);
	full_lc.src_id = bytes[6] << 16 | bytes[7] << 8 | bytes[8];
	console_log(LOGLEVEL_COMM_DMR "    src id: %u\n", full_lc.src_id);
	full_lc.checksum = bytes[9] << 16 | bytes[10] << 8 | bytes[11];
	console_log(LOGLEVEL_COMM_DMR "    reed-solomon checksum: %.6x (", full_lc.checksum);
	switch (result) {
		default:
		case RS_12_9_CORRECT_ERRORS_RESULT_NO_ERRORS_FOUND:
			console_log(LOGLEVEL_COMM_DMR "ok)\n");
			return &full_lc;
		case RS_12_9_CORRECT_ERRORS_RESULT_ERRORS_CORRECTED:
			console_log(LOGLEVEL_COMM_DMR "%u byte errors found and corrected)\n", errors_found);
			return &full_lc;
		case RS_12_9_CORRECT_ERRORS_RESULT_ERRORS_CANT_BE_CORRECTED:
			console_log(LOGLEVEL_COMM_DMR "%u byte errors found - can't correct)\n", errors_found);
			return NULL;
	}
}

dmrpacket_control_emb_lc_t *dmrpacket_control_decode_emb_lc(uint8_t bytes[9]) {
	static dmrpacket_control_emb_lc_t emb_lc;

	if (bytes == NULL)
		return NULL;

	// Embedded LC structure is the same as the full LC's, the only difference is that it doesn't
	// have a Reed-Solomon checksum field.
	if (bytes[0] & 0b1100000)
		emb_lc.call_type = DMR_CALL_TYPE_PRIVATE;
	else
		emb_lc.call_type = DMR_CALL_TYPE_GROUP;

	console_log(LOGLEVEL_COMM_DMR "    call type: %s\n", dmr_get_readable_call_type(emb_lc.call_type));

	emb_lc.dst_id = bytes[3] << 16 | bytes[4] << 8 | bytes[5];
	console_log(LOGLEVEL_COMM_DMR "    dst id: %u\n", emb_lc.dst_id);
	emb_lc.src_id = bytes[6] << 16 | bytes[7] << 8 | bytes[8];
	console_log(LOGLEVEL_COMM_DMR "    src id: %u\n", emb_lc.src_id);

	return &emb_lc;
}

dmrpacket_control_full_lc_t *dmrpacket_control_decode_voice_lc_header(bptc_196_96_data_bits_t *data_bits) {
	uint8_t bytes[12];

	console_log(LOGLEVEL_COMM_DMR "dmrpacket control: decoding voice lc header\n");

	base_bitstobytes(data_bits->bits, 96, bytes, 12);

	// Applying CRC mask to the checksum. See DMR AI. spec. page 143.
	bytes[9] ^= 0x96;
	bytes[10] ^= 0x96;
	bytes[11] ^= 0x96;

	return dmrpacket_control_decode_full_lc(bytes);
}

dmrpacket_control_full_lc_t *dmrpacket_control_decode_terminator_with_lc(bptc_196_96_data_bits_t *data_bits) {
	uint8_t bytes[12];

	console_log(LOGLEVEL_COMM_DMR "dmrpacket control: decoding terminator with lc\n");

	base_bitstobytes(data_bits->bits, 96, bytes, 12);

	// Applying CRC mask to the checksum. See DMR AI. spec. page 143.
	bytes[9] ^= 0x99;
	bytes[10] ^= 0x99;
	bytes[11] ^= 0x99;

	return dmrpacket_control_decode_full_lc(bytes);
}
