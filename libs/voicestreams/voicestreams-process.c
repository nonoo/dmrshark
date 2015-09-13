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

#include <libs/comm/repeaters.h>
#include <libs/comm/ipsc.h>
#include <libs/base/base.h>
#include <libs/config/config-voicestreams.h>

#include <stdio.h>
#include <string.h>

static void voicestreams_savetorawfile(uint8_t *voice_bytes, uint8_t voice_bytes_count, voicestream_t *voicestream) {
	FILE *f;
	char fn[255];
	char *dir;

	if (voice_bytes == NULL || voice_bytes_count == 0 || voicestream == NULL)
		return;

	dir = voicestream->savefiledir;
	if (dir == NULL || strlen(dir) == 0)
		dir = ".";
	snprintf(fn, sizeof(fn), "%s/%s.raw", dir, voicestream->name);

	f = fopen(fn, "a");
	if (!f)
		return;

#if 0
	console_log("voicestreams raw: written %d bytes\n", fwrite(voice_bytes, 1, voice_bytes_count, f));
#else
	fwrite(voice_bytes, 1, voice_bytes_count, f);
#endif
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

	voice_bits = dmrpacket_extract_voice_bits(&ipscpacket->payload_bits);
	for (i = 0; i < sizeof(voice_bits->raw.bits); i += 8)
		voice_bytes[i/8] = base_bitstobyte(&voice_bits->raw.bits[i]);

	if (voicestream->savetorawfile)
		voicestreams_savetorawfile(voice_bytes, sizeof(voice_bytes), voicestream);

#ifdef DECODEVOICE
	decoded_frame = voicestreams_decode_ambe_frame(&voice_bits->ambe_frames.frames[0], voicestream);
	decoded_frame = voicestreams_decode_ambe_frame(&voice_bits->ambe_frames.frames[1], voicestream);
	decoded_frame = voicestreams_decode_ambe_frame(&voice_bits->ambe_frames.frames[2], voicestream);
#endif

	// TODO: streaming
}
