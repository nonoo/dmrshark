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

#if defined(AMBEDECODEVOICE) && defined(MP3ENCODEVOICE)

#include "voicestreams-mp3.h"

#include <libs/daemon/console.h>

#include <string.h>

static void voicestreams_mp3_handleerror(int resultcode) {
	switch (resultcode) {
		case -1: console_log(LOGLEVEL_VOICESTREAMS "voicestreams-mp3 error: encode failed with mp3buf was too small\n"); break;
		case -2: console_log(LOGLEVEL_VOICESTREAMS "voicestreams-mp3 error: encode failed with malloc problem\n"); break;
		case -3: console_log(LOGLEVEL_VOICESTREAMS "voicestreams-mp3 error: encode failed with lame_init_params() not called\n"); break;
		case -4: console_log(LOGLEVEL_VOICESTREAMS "voicestreams-mp3 error: encode failed with psycho acoustic problems\n"); break;
	}
}

// If the function is called with decoded_frame == NULL, then it only empties out the remaining buffer.
voicestreams_mp3_frame_t *voicestreams_mp3_encode(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
	static voicestreams_mp3_frame_t mp3frame;
	int res;

	if (decoded_frame) {
		if (voicestream->mp3_buf_pos < sizeof(voicestream->mp3_buf)/sizeof(voicestream->mp3_buf[0])) {
			memcpy(voicestream->mp3_buf+voicestream->mp3_buf_pos, decoded_frame->samples, VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT*sizeof(decoded_frame->samples[0]));
			voicestream->mp3_buf_pos += VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT;
		}
	}

	if (voicestream->mp3_buf_pos >= sizeof(voicestream->mp3_buf)/sizeof(voicestream->mp3_buf[0]) || decoded_frame == NULL) {
		res = lame_encode_buffer_ieee_float(voicestream->mp3_flags, voicestream->mp3_buf, voicestream->mp3_buf, voicestream->mp3_buf_pos, mp3frame.bytes, sizeof(mp3frame.bytes));
		voicestream->mp3_buf_pos = 0;
		if (res < 0) {
			mp3frame.bytes_size = 0;
			voicestreams_mp3_handleerror(res);
			return NULL;
		}
		mp3frame.bytes_size = res;
		return &mp3frame;
	}
	return NULL;
}

void voicestreams_mp3_encode_flush(voicestream_t *voicestream, voicestreams_mp3_frame_t *mp3frame) {
	int res;

	if (mp3frame == NULL)
		return;

	res = lame_encode_flush(voicestream->mp3_flags, mp3frame->bytes, mp3frame->bytes_size);
	if (res < 0) {
		voicestreams_mp3_handleerror(res);
		return;
	}
	lame_mp3_tags_fid(voicestream->mp3_flags, NULL);
}

void voicestreams_mp3_resetbuf(voicestream_t *voicestream) {
	voicestream->mp3_buf_pos = 0;
}

static void voicestreams_mp3_lamelog(const char *format, va_list ap) {
	console_log(LOGLEVEL_VOICESTREAMS "voicestreams-mp3: lame says: ");
	console_log_va_list(LOGLEVEL_VOICESTREAMS, format, ap);
}

static void voicestreams_mp3_lamelog_err(const char *format, va_list ap) {
	console_log(LOGLEVEL_VOICESTREAMS "voicestreams-mp3 error: lame says: ");
	console_log_va_list(LOGLEVEL_VOICESTREAMS, format, ap);
}

void voicestreams_mp3_init(voicestream_t *voicestream) {
	voicestream->mp3_buf_pos = 0;

	voicestream->mp3_flags = lame_init();

	lame_set_errorf(voicestream->mp3_flags, voicestreams_mp3_lamelog_err);
	lame_set_debugf(voicestream->mp3_flags, voicestreams_mp3_lamelog);
	lame_set_msgf(voicestream->mp3_flags, voicestreams_mp3_lamelog);

	lame_set_num_channels(voicestream->mp3_flags, 1);
	lame_set_in_samplerate(voicestream->mp3_flags, 8000);
	lame_set_brate(voicestream->mp3_flags, voicestream->mp3bitrate);
	lame_set_mode(voicestream->mp3_flags, MONO);
	lame_set_quality(voicestream->mp3_flags, voicestream->mp3quality);
	lame_set_bWriteVbrTag(voicestream->mp3_flags, 0);

	lame_set_VBR(voicestream->mp3_flags, voicestream->mp3vbr);
	lame_set_VBR_q(voicestream->mp3_flags, voicestream->mp3quality);
	lame_set_VBR_min_bitrate_kbps(voicestream->mp3_flags, voicestream->minmp3bitrate);
	lame_set_VBR_max_bitrate_kbps(voicestream->mp3_flags, voicestream->mp3bitrate);

	if (lame_init_params(voicestream->mp3_flags) < 0) {
		lame_close(voicestream->mp3_flags);
		voicestream->mp3_flags = NULL;
		console_log("voicestreams-mp3 error: failed to initialize libmp3lame\n");
	} else
		console_log("voicestreams-mp3: initialized libmp3lame encoder\n");
}

void voicestreams_mp3_deinit(voicestream_t *voicestream) {
	if (voicestream->mp3_flags) {
		lame_close(voicestream->mp3_flags);
		voicestream->mp3_flags = NULL;
	}
}

#endif /* if defined(AMBEDECODEVOICE) && defined(MP3ENCODEVOICE) */
