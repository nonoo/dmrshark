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

static uint16_t vbptc_16_11_get_matrix_free_space(vbptc_16_11_t *vbptc) {
	return vbptc->expected_rows*16-(vbptc->current_col*vbptc->expected_rows+vbptc->current_row);
}

void vbptc_16_11_print_matrix(vbptc_16_11_t *vbptc) {
	loglevel_t loglevel = console_get_loglevel();
	uint8_t row;
	uint8_t col;

	if (!loglevel.flags.debug && !loglevel.flags.comm_dmr)
		return;

	console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "    vbptc (16,11) matrix: ");

	if (vbptc == NULL || vbptc->matrix == NULL || vbptc->expected_rows == 0) {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "empty\n");
		return;
	}

	for (row = 0; row < vbptc->expected_rows; row++) {
		if (row > 0)
			console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "                          ");

		for (col = 0; col < 16; col++) {
			if (col == 11)
				console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR " ");
			console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "%u", vbptc->matrix[row*16+col]);
		}
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "\n");
		if (row == vbptc->expected_rows-2)
			console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "\n");
	}
}

// Adds given embedded signalling data burst to the vbptc_16_11_matrix.
// Returns 1 if the matrix is full.
// As the matrix is transmitted column by column, we store the incoming burst that way.
flag_t vbptc_16_11_add_burst(vbptc_16_11_t *vbptc, flag_t *burst_data, uint8_t burst_data_length) {
	uint16_t matrix_free_space;
	uint16_t bits_to_add;
	uint8_t i;

	if (vbptc == NULL)
		return 0;

	matrix_free_space = vbptc_16_11_get_matrix_free_space(vbptc);
	if (matrix_free_space == 0)
		return 1;

	bits_to_add = min(burst_data_length, matrix_free_space);

	for (i = 0; i < bits_to_add; i++) {
		vbptc->matrix[vbptc->current_col+vbptc->current_row*16] = burst_data[i];
		vbptc->current_row++;
		if (vbptc->current_row == vbptc->expected_rows) {
			vbptc->current_col++;
			vbptc->current_row = 0;
		}
	}

	if (vbptc_16_11_get_matrix_free_space(vbptc) == 0)
		return 1;

	return 0;
}

// Extracts data bits (discarding parity check bits) from the vbptc matrix.
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

// TODO: error correction

void vbptc_16_11_free(vbptc_16_11_t *vbptc) {
	if (vbptc == NULL)
		return;

	if (vbptc->matrix != NULL)
		free(vbptc->matrix);

	memset(vbptc, 0, sizeof(vbptc_16_11_t));
}

// Allocates memory for the given number of expected bits.
void vbptc_16_11_init(vbptc_16_11_t *vbptc, uint8_t expected_rows) {
	uint16_t bytes_to_allocate = expected_rows*16;

	if (vbptc == NULL)
		return;

	vbptc->matrix = (flag_t *)calloc(bytes_to_allocate, 1);
	if (vbptc->matrix == NULL) {
		console_log(LOGLEVEL_DEBUG LOGLEVEL_COMM_DMR "    vbptc (16,11): can't allocate %u bytes for the vbptc matrix\n", bytes_to_allocate);
		return;
	}
	vbptc->expected_rows = expected_rows;
}
