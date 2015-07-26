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

#include <libs/daemon/console.h>
#include <libs/coding/quadres-16-7.h>

#include <string.h>

static char *dmrpacket_emb_get_readable_lcss(dmr_lcss_t lcss) {
	switch (lcss) {
		case DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT: return "single fragment";
		case DMRPACKET_EMB_LCSS_FIRST_FRAGMENT: return "first fragment";
		case DMRPACKET_EMB_LCSS_LAST_FRAGMENT: return "last fragment";
		case DMRPACKET_EMB_LCSS_CONTINUATION: return "continuation";
		default: return "unknown";
	}
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

dmrpacket_emb_binary_t *dmrpacket_emb_extract_from_sync(dmrpacket_payload_sync_bits_t *sync_bits) {
	static dmrpacket_emb_binary_t emb_binary;

	if (sync_bits == NULL)
		return NULL;

	memcpy(emb_binary.bits, sync_bits->bits, 8);
	memcpy(&emb_binary.bits[8], &sync_bits->bits[40], 8);

	return &emb_binary;
}
