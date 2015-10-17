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
#include <libs/dmrpacket/dmrpacket-types.h>

#include <netinet/ip.h>
#ifdef AMBEDECODEVOICE
#include <mbelib.h>
#ifdef MP3ENCODEVOICE
#include <lame/lame.h>
#endif
#endif

#define VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT	160
#define VOICESTREAMS_INVALID_RMS_VALUE					127

#ifdef MP3ENCODEVOICE
 // 8000 samples per sec., 1.25*8000 + 7200
#define VOICESTREAMS_MP3_FRAME_BUFFER_SIZE				17200
// We have to choose a value here which the MP3 encoder can encode. If the number
// of frames are too small, the MP3 encoder won't be able to encode them.
#define VOICESTREAMS_MP3_SILENT_FRAME_SAMPLES_NUM		1280
#define VOICESTREAMS_MP3_SILENT_FRAME_LENGTH_IN_MS		(uint16_t)((VOICESTREAMS_MP3_SILENT_FRAME_SAMPLES_NUM/8000.0)*1000.0)
typedef struct {
	uint8_t bytes[VOICESTREAMS_MP3_FRAME_BUFFER_SIZE];
	uint16_t bytes_size;
} voicestreams_mp3_frame_t;
#endif

typedef struct voicestream_st {
	char *name;
	flag_t enabled;
	flag_t streaming_active_call;
	char *repeaterhosts;
	char *savefiledir;
	flag_t savetorawambefile;
	flag_t savedecodedtorawfile;
	flag_t savedecodedtomp3file;
	uint8_t minmp3bitrate;
	uint8_t mp3bitrate;
	uint8_t mp3quality;
	flag_t mp3vbr;
	flag_t timeslot;
	uint8_t decodequality;
	char *playrawfileatcallstart;
	float rawfileatcallstartgain;
	char *playrawfileatcallend;
	float rawfileatcallendgain;
	float rmsminsamplevalue;

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
	voicestreams_mp3_frame_t silent_mp3_frame;
	// Raw bytes are stored here. These will get encoded to mp3 frames.
	// Must be a multiple of VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT.
	// Note that browsers can't decode MP3 frames encoded from too small PCM chunks.
	// That's why we multiply the default AMBE frame samples count.
	float mp3_buf[VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT*50];
	uint16_t mp3_buf_pos;
#endif
#endif

	struct repeater_t *currently_streaming_repeater;

	struct voicestream_st *next;
} voicestream_t;

char *voicestreams_get_stream_filename(voicestream_t *voicestream, char *extension);

voicestream_t *voicestreams_get_stream_for_repeater(struct in_addr *ip, int timeslot);
voicestream_t *voicestreams_get_stream_by_name(char *name);

void voicestreams_printlist(void);

void voicestreams_init(void);
void voicestreams_deinit(void);

#endif
