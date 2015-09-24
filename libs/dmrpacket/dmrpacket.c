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

#include DEFAULTCONFIG

#include "dmrpacket.h"

#include <libs/base/base.h>
#include <libs/coding/golay-20-8.h>

#include <string.h>

// Extracts the info part of the payload (leaves out slot type and sync parts).
dmrpacket_payload_info_bits_t *dmrpacket_extract_info_bits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_payload_info_bits_t info_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(&info_bits.bits, payload_bits->bits, sizeof(info_bits.bits)/2);
	memcpy(&info_bits.bits[sizeof(info_bits.bits)/2], payload_bits->bits+98+10+48+10, sizeof(info_bits.bits)/2);

	return &info_bits;
}

void dmrpacket_insert_info_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_payload_info_bits_t *info_bits) {
	if (payload_bits == NULL || info_bits == NULL)
		return;

	memcpy(payload_bits->bits, info_bits->bits, sizeof(dmrpacket_payload_info_bits_t)/2);
	memcpy(payload_bits->bits+98+10+48+10, &info_bits->bits[sizeof(dmrpacket_payload_info_bits_t)/2], sizeof(dmrpacket_payload_info_bits_t)/2);
}

dmrpacket_payload_voice_bits_t *dmrpacket_extract_voice_bits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_payload_voice_bits_t voice_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(voice_bits.raw.bits, payload_bits->bits, sizeof(dmrpacket_payload_voice_bits_t)/2);
	memcpy(&voice_bits.raw.bits[sizeof(dmrpacket_payload_voice_bits_t)/2], payload_bits->bits+108+48, sizeof(dmrpacket_payload_voice_bits_t)/2);

	return &voice_bits;
}

void dmrpacket_insert_voice_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_payload_voice_bits_t *voice_bits) {
	if (payload_bits == NULL || voice_bits == NULL)
		return;

	memcpy(payload_bits->bits, voice_bits->raw.bits, sizeof(dmrpacket_payload_voice_bits_t)/2);
	memcpy(payload_bits->bits+108+48, &voice_bits->raw.bits[sizeof(dmrpacket_payload_voice_bits_t)/2], sizeof(dmrpacket_payload_voice_bits_t)/2);
}
