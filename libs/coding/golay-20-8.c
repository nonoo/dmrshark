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

#include "golay-20-8.h"

#include <libs/base/base.h>
#include <libs/daemon/console.h>

#include <string.h>

typedef struct {
	flag_t bits[12];
} golay_20_8_parity_bits_t;

static golay_20_8_parity_bits_t golay_20_8_data_parity_syndromes[256];

// Returns the Golay(20,8) parity bits for the given byte.
static golay_20_8_parity_bits_t *golay_20_8_get_parity_bits(flag_t bits[8]) {
	static golay_20_8_parity_bits_t parity;

	// Multiplying the generator matrix with the given data bits.
	// See DMR AI spec. page 134.
	parity.bits[0] = bits[1] ^ bits[4] ^ bits[5] ^ bits[6] ^ bits[7];
	parity.bits[1] = bits[1] ^ bits[2] ^ bits[4];
	parity.bits[2] = bits[0] ^ bits[2] ^ bits[3] ^ bits[5];
	parity.bits[3] = bits[0] ^ bits[1] ^ bits[3] ^ bits[4] ^ bits[6];
	parity.bits[4] = bits[0] ^ bits[1] ^ bits[2] ^ bits[4] ^ bits[5] ^ bits[7];
	parity.bits[5] = bits[0] ^ bits[2] ^ bits[3] ^ bits[4] ^ bits[7];
	parity.bits[6] = bits[3] ^ bits[6] ^ bits[7];
	parity.bits[7] = bits[0] ^ bits[1] ^ bits[5] ^ bits[6];
	parity.bits[8] = bits[0] ^ bits[1] ^ bits[2] ^ bits[6] ^ bits[7];
	parity.bits[9] = bits[2] ^ bits[3] ^ bits[4] ^ bits[5] ^ bits[6];
	parity.bits[10] = bits[0] ^ bits[3] ^ bits[4] ^ bits[5] ^ bits[6] ^ bits[7];
	parity.bits[11] = bits[1] ^ bits[2] ^ bits[3] ^ bits[5] ^ bits[7];

	return &parity;
}

// Prefills the static data parity syndrome buffer with precalculated parities for each byte value.
static void golay_20_8_calculate_data_parity_syndromes(void) {
	uint16_t i;
	golay_20_8_parity_bits_t *parity_bits = NULL;
	flag_t bits[8];

	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "golay: calculating data parity syndromes\n");

	for (i = 0; i < 256; i++) {
		base_bytetobits(i, bits);
		parity_bits = golay_20_8_get_parity_bits(bits);
		memcpy(golay_20_8_data_parity_syndromes[i].bits, parity_bits->bits, 12);
	}
}

static void golay_20_8_print_bits(flag_t *bits, uint8_t count, flag_t leave_space) {
	uint8_t i;
	loglevel_t loglevel = console_get_loglevel();

	if (!loglevel.flags.debug || !loglevel.flags.comm_dmr)
		return;

	for (i = 0; i < count; i++) {
		if (i == 8 && leave_space) // Leave out a space between 8 bit data and 12 bit parity fields.
			console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR " ");
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "%u", bits[i]);
	}
	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "\n");
}

// Repairs the 8 data bits using a precalculated parity syndrome table.
// Returns 1 if repair was successful or there were no erroneous bits detected.
static flag_t golay_20_8_check_and_repair_data(flag_t bits[20]) {
	uint16_t col;
	int16_t syndrome_location = -1;
	golay_20_8_parity_bits_t *parity_bits = NULL;
	flag_t error_vector_bits[8] = {0,};
	golay_20_8_parity_bits_t syndrome;

	console_log(LOGLEVEL_COMM_DMR "golay: checking data bits\n");

	// Calculating the parity bits for the 8 bit data section.
	parity_bits = golay_20_8_get_parity_bits(bits);
	// Calculating the syndrome.
	for (col = 0; col < 12; col++)
		syndrome.bits[col] = (parity_bits->bits[col] + bits[col+8]) % 2;
	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                 syndrome:          ");
	golay_20_8_print_bits(syndrome.bits, 12, 0);

	// Searching for the given syndrome in the precalculated data parity syndrome buffer.
	for (col = 0; col < 256; col++) {
		if (memcmp(golay_20_8_data_parity_syndromes[col].bits, syndrome.bits, 12) == 0) {
			syndrome_location = col;
			break;
		}
	}

	if (syndrome_location == 0) {
		console_log(LOGLEVEL_COMM_DMR "  no data errors found\n");
		return 1;
	} else if (syndrome_location > 0 && syndrome_location < 256) {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                           trying to repair data\n");

		base_bytetobits(syndrome_location, error_vector_bits); // Error vector is the location of the found syndrome.

		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "  error vector (pos. %.3u): ", syndrome_location);
		golay_20_8_print_bits(error_vector_bits, 8, 1);

		for (col = 0; col < 8; col++) {
			if (error_vector_bits[col]) // Flipping the bits in the input data which are set in the error vector.
				bits[col] = !bits[col];
		}

		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "     error corrected bits: ");
		golay_20_8_print_bits(bits, 20, 1);
		console_log(LOGLEVEL_COMM_DMR "  data errors found and repaired\n");
		return 1;
	} else {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                           couldn't determine syndrome location, can't repair data errors\n");
		console_log(LOGLEVEL_COMM_DMR "  data errors found, but couldn't repair\n");
		return 0;
	}
}

static flag_t golay_20_8_check_and_repair_parity(flag_t bits[20]) {
	static flag_t golay_20_8_parity_check_matrix[] = {
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 0, 0, 0,
		0, 0, 0, 1, 0, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 1, 0,
		0, 0, 0, 0, 0, 0, 0, 1,

		0, 1, 0, 0, 1, 1, 1, 1,
		0, 1, 1, 0, 1, 0, 0, 0,
		1, 0, 1, 1, 0, 1, 0, 0,
		1, 1, 0, 1, 1, 0, 1, 0,
		1, 1, 1, 0, 1, 1, 0, 1,
		1, 0, 1, 1, 1, 0, 0, 1,
		0, 0, 0, 1, 0, 0, 1, 1,
		1, 1, 0, 0, 0, 1, 1, 0,
		1, 1, 1, 0, 0, 0, 1, 1,
		0, 0, 1, 1, 1, 1, 1, 0,
		1, 0, 0, 1, 1, 1, 1, 1,
		0, 1, 1, 1, 0, 1, 0, 1
	};
	uint8_t row;
	uint8_t col;
	uint8_t weight = 0;
	flag_t syndrome[20] = {0,};
	flag_t syndrome2[20] = {0,};
	golay_20_8_parity_bits_t *parity_bits;

	// Calculating the syndrome
	parity_bits = golay_20_8_get_parity_bits(bits);
	for (col = 0; col < 20; col++) {
		syndrome[col] = (parity_bits->bits[col] + bits[col]) % 2;
		if (syndrome[col])
			weight++;
	}

	console_log(LOGLEVEL_COMM_DMR "golay: trying to repair parity bits\n");
	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                 syndrome: ");
	golay_20_8_print_bits(syndrome, 20, 1);
	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                   weight: %u\n", weight);

	if (weight == 0) {
		console_log(LOGLEVEL_COMM_DMR "  no errors found\n");
		return 1;
	} else {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                           searching for minimum weight\n");
		for (row = 0; row < 20; row++) {
			weight = 0;
			for (col = 0; col < 8; col++) {
				syndrome2[col] = (golay_20_8_parity_check_matrix[row*8+col] + syndrome[col+8]) % 2;
				if (syndrome2[col])
					weight++;
			}

			if (weight <= 2) {
				console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                           minimum weight %u found in row %u\n", weight, row);
				console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "  minimum weight syndrome: ");
				golay_20_8_print_bits(syndrome2, 20, 1);

//				for (col = 0; col < 8; col++)
//					bits[col] = (syndrome2[col] + bits[col]) % 2;
				if (row >= 8)
					bits[row] = !bits[row];

				console_log(LOGLEVEL_COMM_DMR "  parity errors found and repaired\n");
				console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                    final: ");
				golay_20_8_print_bits(bits, 20, 1);
				break;
			}
		}
		if (row == 20) {
			console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                           minimum weight not found, can't correct the errors\n");
			console_log(LOGLEVEL_COMM_DMR "  parity errors found, but couldn't repair\n");
			return 0;
		} else
			return 1;
	}
}

flag_t golay_20_8_check_and_repair(flag_t bits[20]) {
	uint8_t retries = 0;

	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "golay:          input bits: ");
	golay_20_8_print_bits(bits, 20, 1);

	if (!golay_20_8_check_and_repair_data(bits)) {
		while (retries++ < 3) {
			golay_20_8_check_and_repair_parity(bits);
			if (golay_20_8_check_and_repair_data(bits))
				return 1;
		}
	} else
		return 1;
	return 0;
}

void golay_20_8_init(void) {
	golay_20_8_calculate_data_parity_syndromes();
}
