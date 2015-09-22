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

#include "dmrpacket-emb.h"

#include <libs/base/base.h>
#include <libs/daemon/console.h>
#include <libs/coding/quadres-16-7.h>

#include <string.h>

// EMB PDU and embedded signalling related functions.

static char *dmrpacket_emb_get_readable_lcss(dmr_emb_lcss_t lcss) {
	switch (lcss) {
		case DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT: return "single fragment";
		case DMRPACKET_EMB_LCSS_FIRST_FRAGMENT: return "first fragment";
		case DMRPACKET_EMB_LCSS_LAST_FRAGMENT: return "last fragment";
		case DMRPACKET_EMB_LCSS_CONTINUATION: return "continuation";
		default: return "unknown";
	}
}

flag_t dmrpacket_emb_is_null_fragment(dmrpacket_emb_signalling_lc_fragment_bits_t *fragment_bits) {
	uint8_t i;
	flag_t is_null = 1;

	for (i = 0; i < sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t); i++) {
		if (fragment_bits->bits[i])
			is_null = 0;
	}
	return is_null;
}

dmrpacket_emb_signalling_lc_bits_t *dmrpacket_emb_deinterleave_lc(dmrpacket_emb_signalling_lc_bits_t *emb_signalling_lc_bits) {
	static dmrpacket_emb_signalling_lc_bits_t deinterleaved_lc;
	flag_t *bits = (flag_t *)emb_signalling_lc_bits;
	uint8_t i;
	uint8_t j;

	if (emb_signalling_lc_bits == NULL)
		return NULL;

	for (i = 0, j = 0; i < 77; i++) {
		switch (i) {
			// See DMR AI. spec. page 124. for the structure of the embedded LC packet.
			case 32: deinterleaved_lc.checksum[0] = bits[i]; break;
			case 43: deinterleaved_lc.checksum[1] = bits[i]; break;
			case 54: deinterleaved_lc.checksum[2] = bits[i]; break;
			case 65: deinterleaved_lc.checksum[3] = bits[i]; break;
			case 76: deinterleaved_lc.checksum[4] = bits[i]; break;
			default: deinterleaved_lc.bits[j++] = bits[i]; break;
		}
	}

	return &deinterleaved_lc;
}

flag_t dmrpacket_emb_check_checksum(dmrpacket_emb_signalling_lc_bits_t *emb_signalling_lc_bits) {
	uint8_t checksum_received;
	uint8_t i;
	uint8_t bytes[9];
	uint16_t checksum_calculated = 0;

	if (emb_signalling_lc_bits == NULL)
		return 0;

	checksum_received = emb_signalling_lc_bits->checksum[0] << 4 | emb_signalling_lc_bits->checksum[1] << 3 |
		emb_signalling_lc_bits->checksum[2] << 2 | emb_signalling_lc_bits->checksum[3] << 1 |
		emb_signalling_lc_bits->checksum[4];

	base_bitstobytes(emb_signalling_lc_bits->bits, 72, bytes, sizeof(bytes));

	for (i = 0; i < 9; i++)
		checksum_calculated += bytes[i];

	checksum_calculated %= 31;

	console_log(LOGLEVEL_DMRLC "    checksum received: 0x%.2x calculated: 0x%.2x (%s)\n", checksum_received, checksum_calculated,
		checksum_received != checksum_calculated ? "error" : "ok");

	return (checksum_calculated == checksum_received);
}

dmrpacket_emb_signalling_lc_fragment_bits_t *dmrpacket_emb_signalling_lc_fragment_extract_from_sync(dmrpacket_sync_bits_t *sync_bits) {
	static dmrpacket_emb_signalling_lc_fragment_bits_t emb_signalling_lc_fragment_bits;

	if (sync_bits == NULL)
		return NULL;

	memcpy(emb_signalling_lc_fragment_bits.bits, &sync_bits->bits[8], 32);

	return &emb_signalling_lc_fragment_bits;
}

dmrpacket_emb_bits_t *dmrpacket_emb_extract_from_sync(dmrpacket_sync_bits_t *sync_bits) {
	static dmrpacket_emb_bits_t emb_bits;

	if (sync_bits == NULL)
		return NULL;

	memcpy(emb_bits.bits, sync_bits->bits, sizeof(dmrpacket_emb_bits_t)/2);
	memcpy(emb_bits.bits+8, sync_bits->bits+sizeof(dmrpacket_emb_bits_t)/2+sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t), sizeof(dmrpacket_emb_bits_t)/2);

	return &emb_bits;
}

dmrpacket_emb_t *dmrpacket_emb_decode(dmrpacket_emb_bits_t *emb_bits) {
	static dmrpacket_emb_t emb;

	if (emb_bits == NULL)
		return NULL;

	console_log(LOGLEVEL_DMRLC "  decoding emb:\n");

	if (!quadres_16_7_check((quadres_16_7_codeword_t *)emb_bits->bits)) {
		console_log("    checksum error\n");
		return NULL;
	}
	console_log("    checksum ok\n");

	if (emb_bits->bits[4] != 0) {
		console_log(LOGLEVEL_DMRLC "    error: pi is not 0\n");
		return NULL;
	}

	emb.cc = emb_bits->bits[0] << 3 | emb_bits->bits[1] << 2 | emb_bits->bits[2] << 1 | emb_bits->bits[3];
	console_log(LOGLEVEL_DMRLC "    cc: %u\n", emb.cc);
	emb.lcss = emb_bits->bits[5] << 1 | emb_bits->bits[6];
	console_log(LOGLEVEL_DMRLC "    lcss: %u (%s)\n", emb.lcss, dmrpacket_emb_get_readable_lcss(emb.lcss));

	return &emb;
}

void dmrpacket_emb_insert_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_emb_bits_t *emb_bits) {
	if (payload_bits == NULL || emb_bits == NULL)
		return;

	memcpy(payload_bits->bits+sizeof(dmrpacket_payload_voice_bits_t)/2, emb_bits->bits, sizeof(dmrpacket_emb_bits_t)/2);
	memcpy(payload_bits->bits+sizeof(dmrpacket_payload_voice_bits_t)/2+sizeof(dmrpacket_emb_bits_t)/2+sizeof(dmrpacket_emb_signalling_lc_fragment_bits_t),
		emb_bits->bits+sizeof(dmrpacket_emb_bits_t)/2, sizeof(dmrpacket_emb_bits_t)/2);
}

dmrpacket_emb_bits_t *dmrpacket_emb_construct_bits(dmr_emb_lcss_t lcss) {
	static dmrpacket_emb_bits_t emb_bits;
	quadres_16_7_parity_bits_t *parity;
	uint8_t data_byte;

	data_byte = 0b00010000 | lcss << 1; // CC = 1
	base_bytetobits(data_byte, emb_bits.bits);
	parity = quadres_16_7_get_parity_bits(emb_bits.bits);
	emb_bits.bits[7] = parity->bits[0];
	emb_bits.bits[8] = parity->bits[1];
	emb_bits.bits[9] = parity->bits[2];
	emb_bits.bits[10] = parity->bits[3];
	emb_bits.bits[11] = parity->bits[4];
	emb_bits.bits[12] = parity->bits[5];
	emb_bits.bits[13] = parity->bits[6];
	emb_bits.bits[14] = parity->bits[7];
	emb_bits.bits[15] = parity->bits[8];

	return &emb_bits;
}
