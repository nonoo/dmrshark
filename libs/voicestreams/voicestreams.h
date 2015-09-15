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

#ifndef VOICESTREAMS_H_
#define VOICESTREAMS_H_

#include <libs/base/types.h>

#include <netinet/ip.h>
#ifdef AMBEDECODEVOICE
#include <mbelib.h>
#ifdef MP3ENCODEVOICE
#include <lame/lame.h>
#endif
#endif

#define VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT 160

typedef struct voicestream_st {
	char *name;
	flag_t enabled;
	char *repeaterhosts;
	char *savefiledir;
	flag_t savetorawfile;
	flag_t savedecodedtorawfile;
	flag_t savedecodedtomp3file;
	uint8_t minmp3bitrate;
	uint8_t mp3bitrate;
	uint8_t mp3quality;
	flag_t mp3vbr;
	flag_t timeslot;
	uint8_t decodequality;

	float rms_vol_buf[VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT*25]; // 0.5 sec. buffer
	uint16_t rms_vol_buf_pos;
	int8_t rms_vol;
	int8_t avg_rms_vol;

#ifdef AMBEDECODEVOICE
	mbe_parms cur_mp;
	mbe_parms prev_mp;
	mbe_parms prev_mp_enhanced;

#ifdef MP3ENCODEVOICE
	lame_global_flags *mp3_flags;
	float mp3_buf[160];
	uint16_t mp3_buf_pos;
#endif
#endif

	struct repeater_t *currently_streaming_repeater;

	struct voicestream_st *next;
} voicestream_t;

char *voicestreams_get_stream_filename(voicestream_t *voicestream, char *extension);

voicestream_t *voicestreams_get_stream_for_repeater(struct in_addr *ip, int timeslot);
void voicestreams_printlist(void);

void voicestreams_init(void);
void voicestreams_deinit(void);

#endif
