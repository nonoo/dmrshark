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

#include "quadres-16-7.h"

#include <libs/base/base.h>
#include <libs/daemon/console.h>

#include <string.h>

static quadres_16_7_parity_bits_t quadres_16_7_valid_data_paritys[128];

// Returns the quadratic residue (16,7,6) parity bits for the given byte.
quadres_16_7_parity_bits_t *quadres_16_7_get_parity_bits(flag_t bits[7]) {
	static quadres_16_7_parity_bits_t parity;

	// Multiplying the generator matrix with the given data bits.
	// See DMR AI spec. page 134.
	parity.bits[0] = bits[1] ^ bits[2] ^ bits[3] ^ bits[4];
	parity.bits[1] = bits[2] ^ bits[3] ^ bits[4] ^ bits[5];
	parity.bits[2] = bits[0] ^ bits[3] ^ bits[4] ^ bits[5] ^ bits[6];
	parity.bits[3] = bits[2] ^ bits[3] ^ bits[5] ^ bits[6];
	parity.bits[4] = bits[1] ^ bits[2] ^ bits[6];
 	parity.bits[5] = bits[0] ^ bits[1] ^ bits[4];
	parity.bits[6] = bits[0] ^ bits[1] ^ bits[2] ^ bits[5];
	parity.bits[7] = bits[0] ^ bits[1] ^ bits[2] ^ bits[3] ^ bits[6];
	parity.bits[8] = bits[0] ^ bits[2] ^ bits[4] ^ bits[5] ^ bits[6];

	return &parity;
}

static void quadres_16_7_calculate_valid_data_paritys(void) {
	uint16_t i;
	quadres_16_7_parity_bits_t *parity_bits = NULL;
	flag_t bits[9];

	console_log("quadres: calculating valid data paritys\n");

	for (i = 0; i < 128; i++) {
		base_bytetobits(i, bits);
		parity_bits = quadres_16_7_get_parity_bits(bits);
		memcpy(quadres_16_7_valid_data_paritys[i].bits, parity_bits->bits, 9);
	}
}

// Returns 1 if the codeword is valid.
flag_t quadres_16_7_check(quadres_16_7_codeword_t *codeword) {
	uint16_t col;
	uint8_t dataval = 0;

	if (codeword == NULL)
		return 0;

	for (col = 0; col < 7; col++) {
		if (codeword->data[col] == 1)
			dataval |= (1 << (7-col));
	}

	if (memcmp(quadres_16_7_valid_data_paritys[dataval].bits, codeword->parity, 9) == 0)
		return 1;

	return 0;
}

// Prefills the static data parity syndrome buffer with precalculated parities for each byte value.
void quadres_16_7_init(void) {
	quadres_16_7_calculate_valid_data_paritys();
}
