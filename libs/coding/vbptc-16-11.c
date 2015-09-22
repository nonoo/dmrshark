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

#include "vbptc-16-11.h"

#include <libs/daemon/console.h>

#include <string.h>
#include <stdlib.h>

typedef struct {
	flag_t bits[5];
} hamming_error_vector_t;

static uint16_t vbptc_16_11_get_matrix_free_space(vbptc_16_11_t *vbptc) {
	return vbptc->expected_rows*16-(vbptc->current_col*vbptc->expected_rows+vbptc->current_row);
}

static void vbptc_16_11_print_matrix(vbptc_16_11_t *vbptc) {
	loglevel_t loglevel = console_get_loglevel();
	uint8_t row;
	uint8_t col;

	if (!loglevel.flags.debug && !loglevel.flags.coding)
		return;

	console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "    vbptc (16,11) matrix: ");

	if (vbptc == NULL || vbptc->matrix == NULL || vbptc->expected_rows == 0) {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "empty\n");
		return;
	}

	for (row = 0; row < vbptc->expected_rows; row++) {
		if (row > 0)
			console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "                          ");

		for (col = 0; col < 16; col++) {
			if (col == 11)
				console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING " ");
			console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "%u", vbptc->matrix[row*16+col]);
		}
		console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "\n");
		if (row == vbptc->expected_rows-2)
			console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "\n");
	}
}

// Adds given embedded signalling data burst to the vbptc_16_11_matrix.
// Returns 0 if the matrix is full and data couldn't be added.
// As the matrix is transmitted column by column, we store the incoming burst that way.
flag_t vbptc_16_11_add_burst(vbptc_16_11_t *vbptc, flag_t *burst_data, uint8_t burst_data_length) {
	uint16_t matrix_free_space;
	uint16_t bits_to_add;
	uint8_t i;

	if (vbptc == NULL)
		return 0;

	matrix_free_space = vbptc_16_11_get_matrix_free_space(vbptc);
	if (matrix_free_space == 0)
		return 0;

	bits_to_add = min(burst_data_length, matrix_free_space);

	for (i = 0; i < bits_to_add; i++) {
		vbptc->matrix[vbptc->current_col+vbptc->current_row*16] = burst_data[i];
		vbptc->current_row++;
		if (vbptc->current_row == vbptc->expected_rows) {
			vbptc->current_col++;
			vbptc->current_row = 0;
		}
	}

	return 1;
}

// Hamming(16, 11, 4) checking of a matrix row (16 total bits, 11 data bits, min. distance: 4)
// See page 136 of the DMR Air Interface protocol specification for the generator matrix.
// A generator matrix looks like this: G = [Ik | P]. The parity check matrix is: H = [-P^T|In-k]
// In binary codes, then -P = P, so the negation is unnecessary. We can get the parity check matrix
// only by transposing the generator matrix. We then take a data row, and multiply it with each row
// of the parity check matrix, then xor each resulting row bits together with the corresponding
// parity check bit. The xor result (error vector) should be 0, if it's not, it can be used
// to determine the location of the erroneous bit using the generator matrix (P).
static void vbptc_16_11_get_parity_bits(flag_t *data_bits, hamming_error_vector_t *error_vector) {
	if (data_bits == NULL || error_vector == NULL)
		return;

	error_vector->bits[0] = (data_bits[0] ^ data_bits[1] ^ data_bits[2] ^ data_bits[3] ^ data_bits[5] ^ data_bits[7] ^ data_bits[8]);
	error_vector->bits[1] = (data_bits[1] ^ data_bits[2] ^ data_bits[3] ^ data_bits[4] ^ data_bits[6] ^ data_bits[8] ^ data_bits[9]);
	error_vector->bits[2] = (data_bits[2] ^ data_bits[3] ^ data_bits[4] ^ data_bits[5] ^ data_bits[7] ^ data_bits[9] ^ data_bits[10]);
	error_vector->bits[3] = (data_bits[0] ^ data_bits[1] ^ data_bits[2] ^ data_bits[4] ^ data_bits[6] ^ data_bits[7] ^ data_bits[10]);
	error_vector->bits[4] = (data_bits[0] ^ data_bits[2] ^ data_bits[5] ^ data_bits[6] ^ data_bits[8] ^ data_bits[9] ^ data_bits[10]);
}

static flag_t vbptc_16_11_check_row(flag_t *data_bits, hamming_error_vector_t *error_vector) {
	if (data_bits == NULL || error_vector == NULL)
		return 0;

	vbptc_16_11_get_parity_bits(data_bits, error_vector);

	error_vector->bits[0] ^= data_bits[11];
	error_vector->bits[1] ^= data_bits[12];
	error_vector->bits[2] ^= data_bits[13];
	error_vector->bits[3] ^= data_bits[14];
	error_vector->bits[4] ^= data_bits[15];

	if (error_vector->bits[0] == 0 &&
		error_vector->bits[1] == 0 &&
		error_vector->bits[2] == 0 &&
		error_vector->bits[3] == 0 &&
		error_vector->bits[4] == 0)
			return 1;

	console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "    vbptc (16,11): hamming(16,11) error vector: %u%u%u%u%u\n",
		error_vector->bits[0],
		error_vector->bits[1],
		error_vector->bits[2],
		error_vector->bits[3],
		error_vector->bits[4]);

	return 0;
}

// Searches for the given error vector in the generator matrix.
// Returns the erroneous bit number if the error vector is found, otherwise it returns -1.
static int8_t vbptc_16_11_find_error_position(hamming_error_vector_t *error_vector) {
	// See page 136 of the DMR AI. spec. for the generator matrix.
	static flag_t hamming_16_11_generator_matrix[] = {
		1,	0,	0,	1,	1,
		1,	1,	0,	1,	0,
		1,	1,	1,	1,	1,
		1,	1,	1,	0,	0,
		0,	1,	1,	1,	0,
		1,	0,	1,	0,	1,
		0,	1,	0,	1,	1,
		1,	0,	1,	1,	0,
		1,	1,	0,	0,	1,
		0,	1,	1,	0,	1,
		0,	0,	1,	1,	1,

		1,	0,	0,	0,	0, // These are used to determine errors in the Hamming checksum bits.
		0,	1,	0,	0,	0,
		0,	0,	1,	0,	0,
		0,	0,	0,	1,	0,
		0,	0,	0,	0,	1
	};
	uint8_t row;

	if (error_vector == NULL)
		return -1;

	for (row = 0; row < 16; row++) {
		if (hamming_16_11_generator_matrix[row*5] == error_vector->bits[0] &&
			hamming_16_11_generator_matrix[row*5+1] == error_vector->bits[1] &&
			hamming_16_11_generator_matrix[row*5+2] == error_vector->bits[2] &&
			hamming_16_11_generator_matrix[row*5+3] == error_vector->bits[3] &&
			hamming_16_11_generator_matrix[row*5+4] == error_vector->bits[4])
				return row;
	}

	return -1;
}

// Checks data for errors and tries to repair them.
flag_t vbptc_16_11_check_and_repair(vbptc_16_11_t *vbptc) {
	hamming_error_vector_t hamming_error_vector = { .bits = {0,} };
	uint8_t row, col;
	int8_t wrongbitnr = -1;
	uint8_t parity;
	flag_t errors_found = 0;
	flag_t result = 1;

	if (vbptc == NULL || vbptc->expected_rows < 2)
		return 0;

	vbptc_16_11_print_matrix(vbptc);

	for (row = 0; row < vbptc->expected_rows-1; row++) { // -1 because the last row contains only single parity check bits.
		if (!vbptc_16_11_check_row(vbptc->matrix+row*16, &hamming_error_vector)) {
			errors_found = 1;
			// Error check failed, checking if we can determine the location of the bit error.
			wrongbitnr = vbptc_16_11_find_error_position(&hamming_error_vector);
			if (wrongbitnr < 0) {
				console_log(LOGLEVEL_CODING "    vbptc (16,11): hamming(16,11) check error, can't repair row #%u\n", row);
				result = 0;
			} else {
				console_log(LOGLEVEL_CODING "    vbptc (16,11): hamming(16,11) check error, fixing bit pos. #%u in row #%u\n", wrongbitnr, row);
				vbptc->matrix[row*16+wrongbitnr] = !vbptc->matrix[row*16+wrongbitnr];

				vbptc_16_11_print_matrix(vbptc);

				if (!vbptc_16_11_check_row(vbptc->matrix+row*16, &hamming_error_vector)) {
					console_log(LOGLEVEL_CODING "    vbptc (16,11): hamming(16,11) check error, couldn't repair row #%u\n", row);
					result = 0;
				}
			}
		}
	}

	for (col = 0; col < 16; col++) {
		parity = 0;
		for (row = 0; row < vbptc->expected_rows-1; row++)
			parity = (parity + vbptc->matrix[row*16+col]) % 2;

		if (parity != vbptc->matrix[(vbptc->expected_rows-1)*16+col]) {
			console_log(LOGLEVEL_CODING "    vbptc (16,11): parity check error in col. #%u\n", col);
			return 0; // As we don't modify the parity bits we can return here immediately.
		}
	}

	if (result && !errors_found)
		console_log(LOGLEVEL_CODING "    vbptc (16,11): received data was error free\n");
	else if (result && errors_found)
		console_log(LOGLEVEL_CODING "    vbptc (16,11): received data had errors which were corrected\n");
	else if (!result)
		console_log(LOGLEVEL_CODING "    vbptc (16,11): received data had errors which couldn't be corrected\n");

	return result;
}

// Extracts data bits (discarding Hamming (16,11) and parity check bits) from the vbptc matrix.
void vbptc_16_11_get_data_bits(vbptc_16_11_t *vbptc, flag_t *bits, uint16_t bits_size) {
	uint8_t row;
	uint8_t col;

	if (vbptc == NULL || vbptc->matrix == NULL)
		return;

	for (row = 0; row < vbptc->expected_rows; row++) {
		for (col = 0; col < 11; col++) {
			if (row*11+col >= bits_size)
				break;

			bits[row*11+col] = vbptc->matrix[row*16+col];
		}
	}
}

void vbptc_16_11_free(vbptc_16_11_t *vbptc) {
	if (vbptc == NULL)
		return;

	if (vbptc->matrix != NULL)
		free(vbptc->matrix);

	memset(vbptc, 0, sizeof(vbptc_16_11_t));
}

void vbptc_16_11_clear(vbptc_16_11_t *vbptc) {
	if (vbptc == NULL)
		return;

	vbptc->current_row = vbptc->current_col = 0;
	memset(vbptc->matrix, 0, vbptc->expected_rows*16);
}

// Allocates memory for the given number of expected bits.
flag_t vbptc_16_11_init(vbptc_16_11_t *vbptc, uint8_t expected_rows) {
	uint16_t bytes_to_allocate = expected_rows*16;

	if (vbptc == NULL)
		return 0;

	vbptc->matrix = (flag_t *)calloc(bytes_to_allocate, 1);
	if (vbptc->matrix == NULL) {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_CODING "    vbptc (16,11): can't allocate %u bytes for the vbptc matrix\n", bytes_to_allocate);
		return 0;
	}
	vbptc->expected_rows = expected_rows;
	return 1;
}
