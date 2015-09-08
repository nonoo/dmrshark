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

static char *dmrpacket_emb_get_readable_lcss(dmr_lcss_t lcss) {
	switch (lcss) {
		case DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT: return "single fragment";
		case DMRPACKET_EMB_LCSS_FIRST_FRAGMENT: return "first fragment";
		case DMRPACKET_EMB_LCSS_LAST_FRAGMENT: return "last fragment";
		case DMRPACKET_EMB_LCSS_CONTINUATION: return "continuation";
		default: return "unknown";
	}
}

dmrpacket_emb_signalling_lc_t *dmrpacket_emb_deinterleave_lc(dmrpacket_emb_signalling_lc_t *emb_signalling_lc) {
	static dmrpacket_emb_signalling_lc_t deinterleaved_lc;
	flag_t *bits = (flag_t *)emb_signalling_lc;
	uint8_t i;
	uint8_t j;

	if (emb_signalling_lc == NULL)
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

flag_t dmrpacket_emb_check_checksum(dmrpacket_emb_signalling_lc_t *emb_signalling_lc) {
	uint8_t checksum = 0;
	uint8_t i;
	uint8_t bytes[9];
	uint16_t sum = 0;

	for (i = 0; i < 5; i++) {
		if (emb_signalling_lc->checksum[i] == 1)
			checksum |= (1 << (4-i));
	}

	base_bitstobytes(emb_signalling_lc->bits, 72, bytes, 9);

	for (i = 0; i < 9; i++)
		sum += bytes[i];

	sum %= 31;

	if (sum != checksum) {
		console_log(LOGLEVEL_COMM_DMR "    incorrect checksum, received %.2x, calculated %.2x\n", checksum, sum);
		return 0;
	} else
		return 1;
}

dmrpacket_emb_signalling_binary_fragment_t *dmrpacket_emb_signalling_extract_from_sync_field(dmrpacket_payload_sync_field_bits_t *sync_field_bits) {
	static dmrpacket_emb_signalling_binary_fragment_t emb_signalling_binary_fragment;

	if (sync_field_bits == NULL)
		return NULL;

	memcpy(emb_signalling_binary_fragment.bits, &sync_field_bits->bits[8], 32);

	return &emb_signalling_binary_fragment;
}

dmrpacket_emb_t *dmrpacket_emb_decode_emb(dmrpacket_emb_binary_t *emb_binary) {
	static dmrpacket_emb_t emb;

	if (emb_binary == NULL || !quadres_16_7_check((quadres_16_7_codeword_t *)emb_binary->bits))
		return NULL;

	console_log(LOGLEVEL_COMM_DMR "dmrpacket emb: found emb with correct parity, decoding\n");

	emb.cc = emb_binary->bits[0] << 3 | emb_binary->bits[1] << 2 | emb_binary->bits[2] << 1 | emb_binary->bits[3];
	console_log(LOGLEVEL_COMM_DMR "  cc: %u\n", emb.cc);
	emb.pi = emb_binary->bits[4];
	console_log(LOGLEVEL_COMM_DMR "  pi: %u\n", emb.pi);
	emb.lcss = emb_binary->bits[5] << 1 | emb_binary->bits[6];
	console_log(LOGLEVEL_COMM_DMR "  lcss: %u (%s)\n", emb.lcss, dmrpacket_emb_get_readable_lcss(emb.lcss));

	return &emb;
}

dmrpacket_emb_binary_t *dmrpacket_emb_extract_from_sync_field(dmrpacket_payload_sync_field_bits_t *sync_field_bits) {
	static dmrpacket_emb_binary_t emb_binary;

	if (sync_field_bits == NULL)
		return NULL;

	memcpy(emb_binary.bits, sync_field_bits->bits, 8);
	memcpy(&emb_binary.bits[8], &sync_field_bits->bits[40], 8);

	return &emb_binary;
}
