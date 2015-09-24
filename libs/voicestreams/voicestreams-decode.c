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

#include "voicestreams-decode.h"

#include <libs/daemon/console.h>

#ifdef AMBEDECODEVOICE

static uint8_t voicestreams_decode_deinterleave_matrix_w[36] = {
	0, 1, 0, 1, 0, 1,
	0, 1, 0, 1, 0, 1,
	0, 1, 0, 1, 0, 1,
	0, 1, 0, 1, 0, 2,
	0, 2, 0, 2, 0, 2,
	0, 2, 0, 2, 0, 2
};

static uint8_t voicestreams_decode_deinterleave_matrix_x[36] = {
	23, 10, 22, 9, 21, 8,
	20, 7, 19, 6, 18, 5,
	17, 4, 16, 3, 15, 2,
	14, 1, 13, 0, 12, 10,
	11, 9, 10, 8, 9, 7,
	8, 6, 7, 5, 6, 4
};

static uint8_t voicestreams_decode_deinterleave_matrix_y[36] = {
	0, 2, 0, 2, 0, 2,
	0, 2, 0, 3, 0, 3,
	1, 3, 1, 3, 1, 3,
	1, 3, 1, 3, 1, 3,
	1, 3, 1, 3, 1, 3,
	1, 3, 1, 3, 1, 3
};

static uint8_t voicestreams_decode_deinterleave_matrix_z[36] = {
	5, 3, 4, 2, 3, 1,
	2, 0, 1, 13, 0, 12,
	22, 11, 21, 10, 20, 9,
	19, 8, 18, 7, 17, 6,
	16, 5, 15, 4, 14, 3,
	13, 2, 12, 1, 11, 0
};

voicestreams_decoded_frame_t *voicestreams_decode_ambe_frame(dmrpacket_payload_ambe_frame_bits_t *ambe_frame_bits, voicestream_t *voicestream) {
	static voicestreams_decoded_frame_t decoded_frame;
	char deinterleaved_ambe_frame_bits[4][24];
	uint8_t j;
	uint8_t *w, *x, *y, *z;
	int errs, errs2;
	char err_str[64];
	char ambe_d[49];

	// Deinterleaving
	w = voicestreams_decode_deinterleave_matrix_w;
	x = voicestreams_decode_deinterleave_matrix_x;
	y = voicestreams_decode_deinterleave_matrix_y;
	z = voicestreams_decode_deinterleave_matrix_z;

	for (j = 0; j < sizeof(dmrpacket_payload_ambe_frame_bits_t); j += 2) {
		deinterleaved_ambe_frame_bits[*w][*x] = ambe_frame_bits->bits[j];
		deinterleaved_ambe_frame_bits[*y][*z] = ambe_frame_bits->bits[j+1];
		w++;
		x++;
		y++;
		z++;
	}

	mbe_initMbeParms(&voicestream->cur_mp, &voicestream->prev_mp, &voicestream->prev_mp_enhanced);
	mbe_processAmbe3600x2450Framef(decoded_frame.samples, &errs, &errs2, err_str, deinterleaved_ambe_frame_bits, ambe_d, &voicestream->cur_mp, &voicestream->prev_mp, &voicestream->prev_mp_enhanced, voicestream->decodequality);

	if (errs2 > 0)
		console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: mbelib decoding errors: %u %s\n", voicestream->name, errs2, err_str);

	for (j = 0; j < VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT; j++)
		decoded_frame.samples[j] /= 32767.0;

	return &decoded_frame;
}

#endif /* ifdef AMBEDECODEVOICE */
