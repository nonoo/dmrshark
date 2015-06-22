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

#include "dmrpacket-data-bptc.h"

#include <libs/daemon/console.h>

#include <stdlib.h>
#include <string.h>

typedef struct {
	flag_t bits[4];
} hamming_error_vector_t;

// Deinterleaves given info bits according to the used BPTC(196,96) interleaving in the DMR standard (see DMR AI spec. page 120).
dmrpacket_payload_info_bits_t *dmrpacket_data_bptc_deinterleave(dmrpacket_payload_info_bits_t *info_bits) {
	static dmrpacket_payload_info_bits_t deint_info_bits;
	int i;

	if (info_bits == NULL)
		return NULL;

	for (i = 0; i < sizeof(info_bits->bits); i++)
		deint_info_bits.bits[i] = info_bits->bits[(i*181) % sizeof(info_bits->bits)];

	return &deint_info_bits;
}


// Hamming(15, 11, 3) checking of a matrix row (15 total bits, 11 data bits, min. distance: 3)
// See page 135 of the DMR Air Interface protocol specification for the generator matrix.
// A generator matrix looks like this: G = [Ik | P]. The parity check matrix is: H = [-P^T|In-k]
// In binary codes, then -P = P, so the negation is unnecessary. We can get the parity check matrix
// only by transposing the generator matrix. We then take a data row, and multiply it with each row
// of the parity check matrix, then xor each resulting row bits together with the corresponding
// parity check bit. The xor result (error vector) should be 0, if it's not, it can be used
// to determine the location of the erroneous bit using the generator matrix (P).
static flag_t dmrpacket_data_bptc_hamming_15_11_3_errorcheck(flag_t *data_bits, hamming_error_vector_t *error_vector) {
	if (data_bits == NULL || error_vector == NULL)
		return 0;

	error_vector->bits[0] = (data_bits[0] ^ data_bits[1] ^ data_bits[2] ^ data_bits[3] ^ data_bits[5] ^ data_bits[7] ^ data_bits[8] ^ data_bits[11]);
	error_vector->bits[1] = (data_bits[1] ^ data_bits[2] ^ data_bits[3] ^ data_bits[4] ^ data_bits[6] ^ data_bits[8] ^ data_bits[9] ^ data_bits[12]);
	error_vector->bits[2] = (data_bits[2] ^ data_bits[3] ^ data_bits[4] ^ data_bits[5] ^ data_bits[7] ^ data_bits[9] ^ data_bits[10] ^ data_bits[13]);
	error_vector->bits[3] = (data_bits[0] ^ data_bits[1] ^ data_bits[2] ^ data_bits[4] ^ data_bits[6] ^ data_bits[7] ^ data_bits[10] ^ data_bits[14]);

	if (error_vector->bits[0] == 0 &&
		error_vector->bits[1] == 0 &&
		error_vector->bits[2] == 0 &&
		error_vector->bits[3] == 0)
			return 1;

	console_log(LOGLEVEL_DEBUG "dmrpacket data bptc hamming(15,11) error vector: %u%u%u%u\n",
		error_vector->bits[0],
		error_vector->bits[1],
		error_vector->bits[2],
		error_vector->bits[3]);

	return 0;
}

// Hamming(13, 9, 3) checking of a matrix column (13 total bits, 9 data bits, min. distance: 3)
static flag_t dmrpacket_data_bptc_hamming_13_9_3_errorcheck(flag_t *data_bits, hamming_error_vector_t *error_vector) {
	if (data_bits == NULL || error_vector == NULL)
		return 0;

	error_vector->bits[0] = (data_bits[0] ^ data_bits[1] ^ data_bits[3] ^ data_bits[5] ^ data_bits[6] ^ data_bits[9]);
	error_vector->bits[1] = (data_bits[0] ^ data_bits[1] ^ data_bits[2] ^ data_bits[4] ^ data_bits[6] ^ data_bits[7] ^ data_bits[10]);
	error_vector->bits[2] = (data_bits[0] ^ data_bits[1] ^ data_bits[2] ^ data_bits[3] ^ data_bits[5] ^ data_bits[7] ^ data_bits[8] ^ data_bits[11]);
	error_vector->bits[3] = (data_bits[0] ^ data_bits[2] ^ data_bits[4] ^ data_bits[5] ^ data_bits[8] ^ data_bits[12]);

	if (error_vector->bits[0] == 0 &&
		error_vector->bits[1] == 0 &&
		error_vector->bits[2] == 0 &&
		error_vector->bits[3] == 0)
			return 1;

	console_log(LOGLEVEL_DEBUG "dmrpacket data bptc hamming(13,9) error vector: %u%u%u%u\n",
		error_vector->bits[0],
		error_vector->bits[1],
		error_vector->bits[2],
		error_vector->bits[3]);

	return 0;
}

static void dmrpacket_data_bptc_display_data_matrix(dmrpacket_payload_info_bits_t *deinterleaved_info_bits) {
	loglevel_t loglevel = console_get_loglevel();
	uint8_t row, col;

	if (!loglevel.flags.debug && !loglevel.flags.comm_dmr)
		return;

	console_log(LOGLEVEL_DEBUG "dmrpacket data bptc matrix:\n");
	for (row = 0; row < 13; row++) {
		console_log(LOGLEVEL_DEBUG "  #%.2u ", row);
		for (col = 0; col < 11; col++) {
			// +1 because the first bit is R(3) and it's not used so we can ignore that.
			console_log(LOGLEVEL_DEBUG "%u", deinterleaved_info_bits->bits[col+row*15+1]);
		}
		console_log(LOGLEVEL_DEBUG " ");
		for (; col < 15; col++) {
			// +1 because the first bit is R(3) and it's not used so we can ignore that.
			console_log(LOGLEVEL_DEBUG "%u", deinterleaved_info_bits->bits[col+row*15+1]);
		}
		console_log(LOGLEVEL_DEBUG "\n");
		if (row == 8)
			console_log(LOGLEVEL_DEBUG "\n");
	}
}

// Searches for the given error vector in the generator matrix.
// Returns the erroneous bit number if the error vector is found, otherwise it returns -1.
static int dmrpacket_data_bptc_find_hamming_15_11_3_error_position(hamming_error_vector_t *error_vector) {
	static flag_t hamming_15_11_generator_matrix[] = {
		1, 0, 0, 1,
		1, 1, 0, 1,
		1, 1, 1, 1,
		1, 1, 1, 0,
		0, 1, 1, 1,
		1, 0, 1, 0,
		0, 1, 0, 1,
		1, 0, 1, 1,
		1, 1, 0, 0,
		0, 1, 1, 0,
		0, 0, 1, 1,

		1, 0, 0, 0, // These are used to determine errors in the Hamming checksum bits.
		0, 1, 0, 0,
		0, 0, 1, 0,
		0, 0, 0, 1
	};
	uint8_t row;

	for (row = 0; row < 15; row++) {
		if (hamming_15_11_generator_matrix[row*4] == error_vector->bits[0] &&
			hamming_15_11_generator_matrix[row*4+1] == error_vector->bits[1] &&
			hamming_15_11_generator_matrix[row*4+2] == error_vector->bits[2] &&
			hamming_15_11_generator_matrix[row*4+3] == error_vector->bits[3])
				return row;
	}

	return -1;
}

// Searches for the given error vector in the generator matrix.
// Returns the erroneous bit number if the error vector is found, otherwise it returns -1.
static int dmrpacket_data_bptc_find_hamming_13_9_3_error_position(hamming_error_vector_t *error_vector) {
	static flag_t hamming_13_9_generator_matrix[] = {
		1, 1, 1, 1,
		1, 1, 1, 0,
		0, 1, 1, 1,
		0, 1, 1, 1,
		0, 1, 0, 1,
		1, 0, 1, 1,
		1, 1, 0, 0,
		0, 1, 1, 0,
		0, 0, 1, 1,

		1, 0, 0, 0, // These are used to determine errors in the Hamming checksum bits.
		0, 1, 0, 0,
		0, 0, 1, 0,
		0, 0, 0, 1
	};
	uint8_t row;

	for (row = 0; row < 13; row++) {
		if (hamming_13_9_generator_matrix[row*4] == error_vector->bits[0] &&
			hamming_13_9_generator_matrix[row*4+1] == error_vector->bits[1] &&
			hamming_13_9_generator_matrix[row*4+2] == error_vector->bits[2] &&
			hamming_13_9_generator_matrix[row*4+3] == error_vector->bits[3])
				return row;
	}

	return -1;
}

// Checks data for errors and tries to repair them.
void dmrpacket_data_bptc_check_and_repair(dmrpacket_payload_info_bits_t *deinterleaved_info_bits) {
	hamming_error_vector_t hamming_error_vector;
	flag_t column_bits[13] = {0,};
	uint8_t row, col;
	int wrongbitnr = -1;

	if (deinterleaved_info_bits == NULL)
		return;

	dmrpacket_data_bptc_display_data_matrix(deinterleaved_info_bits);

	for (col = 0; col < 15; col++) {
		for (row = 0; row < 13; row++) {
			// +1 because the first bit is R(3) and it's not used so we can ignore that.
			column_bits[row] = deinterleaved_info_bits->bits[col+row*15+1];
		}

		if (!dmrpacket_data_bptc_hamming_13_9_3_errorcheck(column_bits, &hamming_error_vector)) {
			// Error check failed, checking if we can determine the location of the bit error.
			wrongbitnr = dmrpacket_data_bptc_find_hamming_13_9_3_error_position(&hamming_error_vector);
			if (wrongbitnr < 0)
				console_log(LOGLEVEL_COMM_DMR "dmrpacket data bptc: hamming(13,9) check error, can't repair column #%u\n", col);
			else {
				// +1 because the first bit is R(3) and it's not used so we can ignore that.
				console_log(LOGLEVEL_COMM_DMR "dmrpacket data bptc: hamming(13,9) check error, fixing bit row #%u col #%u\n", wrongbitnr, col);
				deinterleaved_info_bits->bits[col+wrongbitnr*15+1] = !deinterleaved_info_bits->bits[col+wrongbitnr*15+1];

				dmrpacket_data_bptc_display_data_matrix(deinterleaved_info_bits);

				for (row = 0; row < 13; row++) {
					// +1 because the first bit is R(3) and it's not used so we can ignore that.
					column_bits[row] = deinterleaved_info_bits->bits[col+row*15+1];
				}

				if (!dmrpacket_data_bptc_hamming_13_9_3_errorcheck(column_bits, &hamming_error_vector))
					console_log(LOGLEVEL_COMM_DMR "dmrpacket data bptc: hamming(13,9) check error, couldn't repair column #%u\n", col);
			}
		}
	}

	for (row = 0; row < 9; row++) {
		// +1 because the first bit is R(3) and it's not used so we can ignore that.
		if (!dmrpacket_data_bptc_hamming_15_11_3_errorcheck(&deinterleaved_info_bits->bits[row*15+1], &hamming_error_vector)) {
			// Error check failed, checking if we can determine the location of the bit error.
			wrongbitnr = dmrpacket_data_bptc_find_hamming_15_11_3_error_position(&hamming_error_vector);
			if (wrongbitnr < 0)
				console_log(LOGLEVEL_COMM_DMR "dmrpacket data bptc: hamming(15,11) check error in row %u, can't repair\n", row);
			else {
				// +1 because the first bit is R(3) and it's not used so we can ignore that.
				console_log(LOGLEVEL_COMM_DMR "dmrpacket data bptc: hamming(15,11) check error, fixing bit row #%u col #%u\n", row, wrongbitnr);
				deinterleaved_info_bits->bits[row*15+wrongbitnr+1] = !deinterleaved_info_bits->bits[row*15+wrongbitnr+1];

				dmrpacket_data_bptc_display_data_matrix(deinterleaved_info_bits);

				if (!dmrpacket_data_bptc_hamming_15_11_3_errorcheck(&deinterleaved_info_bits->bits[row*15+1], &hamming_error_vector))
					console_log(LOGLEVEL_COMM_DMR "dmrpacket data bptc: hamming(15,11) check error, couldn't repair row #%u\n", row);
			}
		}
	}
}

// Extracts the data bits from the given deinterleaved info bits array (discards BPTC bits).
dmrpacket_payload_bptc_data_bits_t *dmrpacket_data_bptc_extractdata(dmrpacket_payload_info_bits_t *deinterleaved_info_bits) {
	static dmrpacket_payload_bptc_data_bits_t data_bits;

	if (deinterleaved_info_bits == NULL)
		return NULL;

	memcpy(&data_bits.bits[0], deinterleaved_info_bits->bits+4, 8);
	memcpy(&data_bits.bits[8], deinterleaved_info_bits->bits+16, 11);
	memcpy(&data_bits.bits[19], deinterleaved_info_bits->bits+31, 11);
	memcpy(&data_bits.bits[30], deinterleaved_info_bits->bits+46, 11);
	memcpy(&data_bits.bits[41], deinterleaved_info_bits->bits+61, 11);
	memcpy(&data_bits.bits[52], deinterleaved_info_bits->bits+76, 11);
	memcpy(&data_bits.bits[63], deinterleaved_info_bits->bits+91, 11);
	memcpy(&data_bits.bits[74], deinterleaved_info_bits->bits+106, 11);
	memcpy(&data_bits.bits[85], deinterleaved_info_bits->bits+121, 11);

	return &data_bits;
}
