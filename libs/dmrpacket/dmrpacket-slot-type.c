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

#include "dmrpacket-slot-type.h"

#include <libs/coding/golay-20-8.h>
#include <libs/base/base.h>
#include <libs/daemon/console.h>

#include <stdlib.h>
#include <string.h>

dmrpacket_slot_type_bits_t *dmrpacket_slot_type_extract_bits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_slot_type_bits_t slot_type_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(&slot_type_bits.bits, payload_bits->bits+98, sizeof(slot_type_bits.bits)/2);
	memcpy(&slot_type_bits.bits[sizeof(slot_type_bits.bits)/2], payload_bits->bits+98+10+48, sizeof(slot_type_bits.bits)/2);

	return &slot_type_bits;
}

void dmrpacket_slot_type_insert_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_slot_type_bits_t *slot_type_bits) {
	if (payload_bits == NULL || slot_type_bits == NULL)
		return;

	memcpy(payload_bits->bits+sizeof(dmrpacket_payload_info_bits_t)/2, slot_type_bits->bits, sizeof(dmrpacket_slot_type_bits_t)/2);
	memcpy(payload_bits->bits+sizeof(dmrpacket_payload_info_bits_t)/2+sizeof(dmrpacket_slot_type_bits_t)/2+sizeof(dmrpacket_sync_bits_t),
		&slot_type_bits->bits[sizeof(dmrpacket_slot_type_bits_t)/2], sizeof(dmrpacket_slot_type_bits_t)/2);
}

dmrpacket_slot_type_bits_t *dmrpacket_slot_type_construct_bits(dmr_color_code_t cc, dmrpacket_data_type_t data_type) {
	static dmrpacket_slot_type_bits_t slot_type_bits;
	golay_20_8_parity_bits_t *golay_20_8_parity_bits;
	flag_t bits[8];

	base_bytetobits(cc, bits);
	slot_type_bits.bits[0] = bits[4];
	slot_type_bits.bits[1] = bits[5];
	slot_type_bits.bits[2] = bits[6];
	slot_type_bits.bits[3] = bits[7];
	base_bytetobits(data_type, bits);
	slot_type_bits.bits[4] = bits[4];
	slot_type_bits.bits[5] = bits[5];
	slot_type_bits.bits[6] = bits[6];
	slot_type_bits.bits[7] = bits[7];
	golay_20_8_parity_bits = golay_20_8_get_parity_bits(slot_type_bits.bits);
	slot_type_bits.bits[8] = golay_20_8_parity_bits->bits[0];
	slot_type_bits.bits[9] = golay_20_8_parity_bits->bits[1];
	slot_type_bits.bits[10] = golay_20_8_parity_bits->bits[2];
	slot_type_bits.bits[11] = golay_20_8_parity_bits->bits[3];
	slot_type_bits.bits[12] = golay_20_8_parity_bits->bits[4];
	slot_type_bits.bits[13] = golay_20_8_parity_bits->bits[5];
	slot_type_bits.bits[14] = golay_20_8_parity_bits->bits[6];
	slot_type_bits.bits[15] = golay_20_8_parity_bits->bits[7];
	slot_type_bits.bits[16] = golay_20_8_parity_bits->bits[8];
	slot_type_bits.bits[17] = golay_20_8_parity_bits->bits[9];
	slot_type_bits.bits[18] = golay_20_8_parity_bits->bits[10];
	slot_type_bits.bits[19] = golay_20_8_parity_bits->bits[11];

	return &slot_type_bits;
}

dmrpacket_slot_type_t *dmrpacket_slot_type_decode(dmrpacket_slot_type_bits_t *slot_type_bits) {
	static dmrpacket_slot_type_t slot_type;

	console_log(LOGLEVEL_DMRLC "  decoding slot type:\n");

	if (!golay_20_8_check_and_repair(slot_type_bits->bits)) {
		console_log(LOGLEVEL_DMRLC "    parity error\n");
		return NULL;
	}

	console_log(LOGLEVEL_DMRLC "    parity ok\n");
	slot_type.cc = slot_type_bits->bits[0] << 3 | slot_type_bits->bits[1] << 2 | slot_type_bits->bits[2] << 1 | slot_type_bits->bits[3];
	console_log(LOGLEVEL_DMRLC "    cc: %u\n", slot_type.cc);
	slot_type.data_type = slot_type_bits->bits[4] << 3 | slot_type_bits->bits[5] << 2 | slot_type_bits->bits[6] << 1 | slot_type_bits->bits[7];
	console_log(LOGLEVEL_DMRLC "    data type: %s (%.2x)\n", dmrpacket_data_get_readable_data_type(slot_type.data_type), slot_type.data_type);

	return &slot_type;
}
