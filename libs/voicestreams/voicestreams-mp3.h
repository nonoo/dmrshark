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

#ifndef VOICESTREAMS_MP3_H_
#define VOICESTREAMS_MP3_H_

#include "voicestreams-decode.h"

typedef struct {
	uint8_t bytes[17200]; // 8000 samples per sec., 1.25*8000 + 7200
	uint16_t bytes_size;
} voicestreams_mp3_frame_t;

voicestreams_mp3_frame_t *voicestreams_mp3_encode(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame);
void voicestreams_mp3_encode_flush(voicestream_t *voicestream, voicestreams_mp3_frame_t *mp3frame);
void voicestreams_mp3_resetbuf(voicestream_t *voicestream);

void voicestreams_mp3_init(voicestream_t *voicestream);
void voicestreams_mp3_deinit(voicestream_t *voicestream);

#endif
