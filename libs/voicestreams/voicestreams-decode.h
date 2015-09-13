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

#ifndef VOICESTREAMS_DECODE_H_
#define VOICESTREAMS_DECODE_H_

#include "voicestreams.h"

#include <libs/base/types.h>
#include <libs/dmrpacket/dmrpacket.h>

#define VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT 160

typedef struct {
	int16_t samples[VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT];
} voicestreams_decoded_frame_t;

voicestreams_decoded_frame_t *voicestreams_decode_ambe_frame(dmrpacket_payload_ambe_frame_bits_t *ambe_frame_bits, voicestream_t *voicestream);

#endif
