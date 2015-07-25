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
#include <libs/coding/crc.h>
#include <libs/daemon/console.h>

#include <stdlib.h>

dmrpacket_control_full_lc_t *dmrpacket_control_decode_full_lc(bptc_196_96_data_bits_t *data_bits) {
	static dmrpacket_control_full_lc_t full_lc;
	uint8_t bytes[12];

	if (data_bits == NULL)
		return NULL;

	console_log(LOGLEVEL_COMM_DMR "dmrpacket control: decoding full lc header\n");

	if (data_bits->bits[6] == 1 && data_bits->bits[7] == 1)
		full_lc.call_type = DMR_CALL_TYPE_PRIVATE;
	else
		full_lc.call_type = DMR_CALL_TYPE_GROUP;

	console_log(LOGLEVEL_COMM_DMR "  call type: %s\n", dmr_get_readable_call_type(full_lc.call_type));

	base_bitstobytes(data_bits->bits, 96, bytes, 12);
	full_lc.dst_id = bytes[3] << 16 | bytes[4] << 8 | bytes[5];
	console_log(LOGLEVEL_COMM_DMR "  dst id: %u\n", full_lc.dst_id);
	full_lc.src_id = bytes[6] << 16 | bytes[7] << 8 | bytes[8];
	console_log(LOGLEVEL_COMM_DMR "  src id: %u\n", full_lc.src_id);
	full_lc.checksum = bytes[9] << 16 | bytes[10] << 8 | bytes[11];
	console_log(LOGLEVEL_COMM_DMR "  checksum: %.6x\n", full_lc.checksum);
	// TODO: reed solomon error checking
	return &full_lc;
}
