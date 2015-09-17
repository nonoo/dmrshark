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

#include "voicestreams.h"
#include "voicestreams-process.h"
#include "voicestreams-decode.h"
#include "voicestreams-mp3.h"

#include <libs/daemon/console.h>
#include <libs/comm/repeaters.h>
#include <libs/comm/httpserver.h>
#include <libs/comm/ipsc.h>
#include <libs/base/base.h>
#include <libs/config/config-voicestreams.h>

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

static void voicestreams_process_savetorawfile(uint8_t *voice_bytes, uint8_t voice_bytes_count, voicestream_t *voicestream) {
	FILE *f;
	char *fn;
	size_t saved_bytes;

	if (voice_bytes == NULL || voice_bytes_count == 0 || voicestream == NULL)
		return;

	fn = voicestreams_get_stream_filename(voicestream, ".raw");
	f = fopen(fn, "a");
	if (!f) {
		console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s] error: can't save voice packet to %s\n", voicestream->name, fn);
		return;
	}
	saved_bytes = fwrite(voice_bytes, 1, voice_bytes_count, f);
	fclose(f);
	console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: saved %u voice packet bytes to %s\n", voicestream->name, saved_bytes, fn);
}

static void voicestreams_process_rms_vol_calc(voicestream_t *voicestream) {
	uint16_t i;
	uint16_t elements = 0;
	float rms_vol = 0;

	if (voicestream == NULL)
		return;

	if (voicestream->rms_vol_buf_pos == 0) {
		console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: not enough data collected to calculate rms volume\n", voicestream->name);
		return;
	}

	for (i = 0; i < voicestream->rms_vol_buf_pos; i++) {
		if (fabsf(voicestream->rms_vol_buf[i]) > voicestream->rmsminsamplevalue) {
			rms_vol += voicestream->rms_vol_buf[i]*voicestream->rms_vol_buf[i];
			elements++;
		}
	}

	rms_vol /= elements;
	voicestream->rms_vol_buf_pos = 0;
	if (isnan(rms_vol)) {
		console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: calculated rms volume is 0, ignoring\n", voicestream->name);
		return;
	}
	rms_vol = sqrtf(rms_vol);
	rms_vol = 10*log10f(rms_vol/1.0);

	voicestream->rms_vol = (int8_t)rms_vol;
	if (voicestream->avg_rms_vol == VOICESTREAMS_INVALID_RMS_VALUE)
		voicestream->avg_rms_vol = voicestream->rms_vol;
	else {
		voicestream->avg_rms_vol += voicestream->rms_vol;
		voicestream->avg_rms_vol /= 2.0;
	}
	console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: calculated rms volume is %ddB, avg: %ddB\n", voicestream->name, voicestream->rms_vol, voicestream->avg_rms_vol);
}

static void voicestreams_process_rms_vol_calc_addtobuf(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
	uint16_t rms_vol_buf_remaining_space;
	uint16_t samples_to_copy;

	if (voicestream == NULL || decoded_frame == NULL)
		return;

	rms_vol_buf_remaining_space = sizeof(voicestream->rms_vol_buf)/sizeof(voicestream->rms_vol_buf[0])-voicestream->rms_vol_buf_pos;
	samples_to_copy = min(rms_vol_buf_remaining_space, VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT);
	memcpy(&voicestream->rms_vol_buf[voicestream->rms_vol_buf_pos], decoded_frame->samples, samples_to_copy*sizeof(voicestream->rms_vol_buf[0]));
	voicestream->rms_vol_buf_pos += samples_to_copy;

	if (voicestream->rms_vol_buf_pos == sizeof(voicestream->rms_vol_buf)/sizeof(voicestream->rms_vol_buf[0]))
		voicestreams_process_rms_vol_calc(voicestream);
}

static void voicestreams_process_apply_gain(voicestreams_decoded_frame_t *decoded_frame) {
	uint8_t i;

	for (i = 0; i < VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT; i++) {
		decoded_frame->samples[i] *= 15.0;

		// Clipping
		if (decoded_frame->samples[i] > 1.0f)
			decoded_frame->samples[i] = 1.0f;
		else if (decoded_frame->samples[i] < -1.0f)
			decoded_frame->samples[i] = -1.0f;
	}
}

static void voicestreams_process_mp3(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
#ifdef MP3ENCODEVOICE
	FILE *f;
	char *fn;
	size_t saved_items;
	voicestreams_mp3_frame_t *mp3frame;

	if (voicestream == NULL) // Calling the function with decoded_frame == NULL is allowed.
		return;

	// It's safe to call this function with decoded_frame == NULL.
	mp3frame = voicestreams_mp3_encode(voicestream, decoded_frame);
	if (mp3frame == NULL)
		return;
	if (decoded_frame == NULL)
		voicestreams_mp3_encode_flush(voicestream, mp3frame); // This closes the call's mp3 segment.

	if (voicestream->savedecodedtomp3file) {
		fn = voicestreams_get_stream_filename(voicestream, ".mp3");
		f = fopen(fn, "a");
		if (!f) {
			console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s] error: can't save mp3 frame to %s\n", voicestream->name, fn);
			return;
		}
		saved_items = fwrite(mp3frame->bytes, 1, mp3frame->bytes_size, f);
		fclose(f);
		console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: saved %u mp3 frame bytes to %s\n", voicestream->name, saved_items, fn);
	}

	httpserver_sendtoclients(voicestream, mp3frame->bytes, mp3frame->bytes_size);
#endif
}

static void voicestreams_play_raw_file(voicestream_t *voicestream, char *filepath) {
	FILE *f;
	voicestreams_decoded_frame_t frame;

	if (voicestream == NULL || filepath == NULL || filepath[0] == 0)
		return;

	f = fopen(filepath, "r");
	if (!f) {
		console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: can't play raw file %s\n", voicestream->name, filepath);
		return;
	}
	console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: playing raw file %s\n", voicestream->name, filepath);
	while (!feof(f)) {
		memset(frame.samples, 0, sizeof(frame.samples));
		if (fread(frame.samples, 1, sizeof(frame.samples), f) > 0)
			voicestreams_process_mp3(voicestream, &frame);
	}
	fclose(f);
}

static void voicestreams_process_decoded_frame(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
	FILE *f;
	char *fn;
	size_t saved_items;

	if (voicestream == NULL || decoded_frame == NULL)
		return;

	voicestreams_process_apply_gain(decoded_frame);
	voicestreams_process_rms_vol_calc_addtobuf(voicestream, decoded_frame);

	if (voicestream->savedecodedtorawfile) {
		fn = voicestreams_get_stream_filename(voicestream, ".decoded.raw");
		f = fopen(fn, "a");
		if (!f) {
			console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s] error: can't save decoded voice packet to %s\n", voicestream->name, fn);
			return;
		}
		saved_items = fwrite(decoded_frame->samples, sizeof(decoded_frame->samples[0]), VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT, f);
		fclose(f);
		console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: saved %u decoded voice packet bytes to %s\n", voicestream->name, saved_items*sizeof(decoded_frame->samples[0]), fn);
	}

	voicestreams_process_mp3(voicestream, decoded_frame);
}

void voicestreams_process_call_start(voicestream_t *voicestream, repeater_t *repeater) {
	if (!voicestream || !voicestream->enabled)
		return;

	console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: call start on repeater %s\n", voicestream->name, repeaters_get_display_string(repeater));

	voicestream->currently_streaming_repeater = (struct repeater_t *)repeater;
	voicestream->rms_vol = voicestream->avg_rms_vol = VOICESTREAMS_INVALID_RMS_VALUE;
	voicestream->rms_vol_buf_pos = 0;
	voicestreams_mp3_resetbuf(voicestream);

	voicestreams_play_raw_file(voicestream, voicestream->playrawfileatcallstart);
}

void voicestreams_process_call_end(voicestream_t *voicestream, repeater_t *repeater) {
	uint8_t i;
	voicestreams_decoded_frame_t zero_frame = { .samples = { 0, } };

	if (!voicestream || !voicestream->enabled)
		return;

	voicestreams_process_rms_vol_calc(voicestream);
	voicestreams_play_raw_file(voicestream, voicestream->playrawfileatcallend);

	console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: call end on repeater %s\n", voicestream->name, repeaters_get_display_string(repeater));
	voicestream->currently_streaming_repeater = NULL;

	// Flushing out the buffer.
	for (i = 0; i < 20; i++)
		voicestreams_process_mp3(voicestream, &zero_frame);
	voicestreams_process_mp3(voicestream, NULL);
}

void voicestreams_processpacket(ipscpacket_t *ipscpacket, repeater_t *repeater) {
	voicestream_t *voicestream;
	dmrpacket_payload_voice_bits_t *voice_bits;
	uint8_t i;
	uint8_t voice_bytes[sizeof(dmrpacket_payload_voice_bits_t)/8];
#ifdef AMBEDECODEVOICE
	voicestreams_decoded_frame_t *decoded_frame;
#endif

	if (ipscpacket == NULL || repeater == NULL)
		return;

	switch (ipscpacket->slot_type) {
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_A: // Only processing voice data packets.
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_B:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_C:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_D:
		case IPSCPACKET_SLOT_TYPE_VOICE_DATA_E:
			break;
		default:
			return;
	}

	voicestream = repeater->slot[ipscpacket->timeslot-1].voicestream;
	if (voicestream == NULL)
		return;

	if (!voicestream->enabled)
		return;

	// Some listed repeater has already streaming on this stream?
	if ((repeater_t *)voicestream->currently_streaming_repeater != repeater)
		return;

	console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: processing packet from %s\n", voicestream->name, repeaters_get_display_string((repeater_t *)voicestream->currently_streaming_repeater));

	voice_bits = dmrpacket_extract_voice_bits(&ipscpacket->payload_bits);
	for (i = 0; i < sizeof(voice_bits->raw.bits); i += 8)
		voice_bytes[i/8] = base_bitstobyte(&voice_bits->raw.bits[i]);

	if (voicestream->savetorawfile)
		voicestreams_process_savetorawfile(voice_bytes, sizeof(voice_bytes), voicestream);

#ifdef AMBEDECODEVOICE
	console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: decoding frame 0\n", voicestream->name);
	decoded_frame = voicestreams_decode_ambe_frame(&voice_bits->ambe_frames.frames[0], voicestream);
	voicestreams_process_decoded_frame(voicestream, decoded_frame);

	console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: decoding frame 1\n", voicestream->name);
	decoded_frame = voicestreams_decode_ambe_frame(&voice_bits->ambe_frames.frames[1], voicestream);
	voicestreams_process_decoded_frame(voicestream, decoded_frame);

	console_log(LOGLEVEL_VOICESTREAMS LOGLEVEL_DEBUG "voicestreams [%s]: decoding frame 2\n", voicestream->name);
	decoded_frame = voicestreams_decode_ambe_frame(&voice_bits->ambe_frames.frames[2], voicestream);
	voicestreams_process_decoded_frame(voicestream, decoded_frame);
#endif
}
