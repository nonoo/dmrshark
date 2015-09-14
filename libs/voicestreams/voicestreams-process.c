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

#include <libs/daemon/console.h>
#include <libs/comm/repeaters.h>
#include <libs/comm/ipsc.h>
#include <libs/base/base.h>
#include <libs/config/config-voicestreams.h>

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

#define VOICESTREAMS_PROCESS_AGC_DEFAULT_GAIN 18.0

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

static void voicestreams_process_apply_agc(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
	uint8_t i, n;
	float gainfactor, gaindelta, maxbuf;
	float aout_abs, max;

	if (decoded_frame == NULL)
		return;

	for (i = 0; i < VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT; i++) {
		// Detect max. level
		max = 0;
		for (n = 0; n < VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT; n++) {
			aout_abs = fabsf(decoded_frame->samples[n]);
			if (aout_abs > max)
				max = aout_abs;
		}
		voicestream->agc_aout_max_buf[voicestream->agc_aout_max_buf_idx++] = max;
		if (voicestream->agc_aout_max_buf_idx > 24)
			voicestream->agc_aout_max_buf_idx = 0;

		// Lookup max. history
		for (n = 0; n < 25; n++) {
			maxbuf = voicestream->agc_aout_max_buf[n];
			if (maxbuf > max)
				max = maxbuf;
		}

		// Determine optimal gain level
		if (max > 0.0f)
			gainfactor = (32767.0f / max);
		else
			gainfactor = VOICESTREAMS_PROCESS_AGC_DEFAULT_GAIN;

		if (gainfactor < voicestream->agc_needed_gain) {
			voicestream->agc_needed_gain = gainfactor;
			gaindelta = 0.0f;
		} else {
			if (gainfactor > VOICESTREAMS_PROCESS_AGC_DEFAULT_GAIN)
				gainfactor = VOICESTREAMS_PROCESS_AGC_DEFAULT_GAIN;

			gaindelta = gainfactor - voicestream->agc_needed_gain;
			if (gaindelta > (0.05f * voicestream->agc_needed_gain))
				gaindelta = (0.05f * voicestream->agc_needed_gain);
		}

		// Adjust output gain
		voicestream->agc_needed_gain += gaindelta;

		decoded_frame->samples[i] *= voicestream->agc_needed_gain;
		if (decoded_frame->samples[i] > 1.0f)
			decoded_frame->samples[i] = 1.0f;
		else if (decoded_frame->samples[i] < -1.0f)
			decoded_frame->samples[i] = -1.0f;
	}
}

float voicestreams_process_rms_calc(voicestream_t *voicestream) {
	uint16_t i;
	float rms = 0;

	for (i = 0; i < voicestream->rms_buf_pos; i++)
		rms += voicestream->rms_buf[i]*voicestream->rms_buf[i];

	rms /= voicestream->rms_buf_pos;
	return sqrtf(rms);
}

static void voicestreams_process_rms_calc_addtobuf(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
	uint16_t rms_buf_remaining_space;
	uint16_t samples_to_copy;
	int8_t rms;

	if (voicestream == NULL)
		return;

	rms_buf_remaining_space = sizeof(voicestream->rms_buf)/sizeof(voicestream->rms_buf[0])-voicestream->rms_buf_pos;
	samples_to_copy = min(rms_buf_remaining_space, VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT);
	memcpy(&voicestream->rms_buf[voicestream->rms_buf_pos], decoded_frame->samples, samples_to_copy*sizeof(voicestream->rms_buf[0]));
	voicestream->rms_buf_pos += samples_to_copy;

	if (voicestream->rms_buf_pos == sizeof(voicestream->rms_buf)/sizeof(voicestream->rms_buf[0])) {
		rms = 10*log10f(voicestreams_process_rms_calc(voicestream)/32767.0);
		console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: calculated rms volume is %ddB\n", voicestream->name, rms);
		voicestream->rms_buf_pos = 0;
	}
}

static void voicestreams_process_apply_gain(voicestreams_decoded_frame_t *decoded_frame) {
	uint8_t i;

	for (i = 0; i < VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT; i++)
		decoded_frame->samples[i] *= 2;
}

static void voicestreams_process_decoded_frame(voicestream_t *voicestream, voicestreams_decoded_frame_t *decoded_frame) {
	if (decoded_frame == NULL)
		return;

	//voicestreams_process_apply_gain(decoded_frame);
	voicestreams_process_apply_agc(voicestream, decoded_frame);
	voicestreams_process_rms_calc_addtobuf(voicestream, decoded_frame);

	FILE *f = fopen("out.raw", "a");
	fwrite(decoded_frame->samples, sizeof(decoded_frame->samples[0]), VOICESTREAMS_DECODED_AMBE_FRAME_SAMPLES_COUNT, f);
	fclose(f);
}

void voicestreams_processpacket(ipscpacket_t *ipscpacket, repeater_t *repeater) {
	voicestream_t *voicestream;
	dmrpacket_payload_voice_bits_t *voice_bits;
	uint8_t i;
	uint8_t voice_bytes[sizeof(dmrpacket_payload_voice_bits_t)/8];
#ifdef DECODEVOICE
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

#ifdef DECODEVOICE
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

	// TODO: streaming
}

void voicestreams_process_call_start(voicestream_t *voicestream, repeater_t *repeater) {
	if (!voicestream || !voicestream->enabled)
		return;

	console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: call start on repeater %s\n", voicestream->name, repeaters_get_display_string(repeater));

	voicestream->currently_streaming_repeater = (struct repeater_t *)repeater;
	voicestream->rms_buf_pos = 0;
	voicestream->agc_needed_gain = 25;
	voicestream->agc_aout_max_buf_idx = 0;
}

void voicestreams_process_call_end(voicestream_t *voicestream, repeater_t *repeater) {
	if (!voicestream || !voicestream->enabled)
		return;

	console_log(LOGLEVEL_VOICESTREAMS "voicestreams [%s]: call end on repeater %s\n", voicestream->name, repeaters_get_display_string(repeater));

	voicestreams_process_rms_calc(voicestream);
	voicestream->currently_streaming_repeater = NULL;
}
