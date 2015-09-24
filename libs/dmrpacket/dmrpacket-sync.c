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

#include "dmrpacket-sync.h"
#include "dmrpacket-slot-type.h"

#include <libs/base/base.h>

#include <stdlib.h>
#include <string.h>

// See DMR AI spec. page 89.
static uint8_t dmrpacket_sync_pattern_bs_sourced_voice[6] = { 0x75, 0x5F, 0xD7, 0xDF, 0x75, 0xF7 };
static uint8_t dmrpacket_sync_pattern_bs_sourced_data[6] = { 0xDF, 0xF5, 0x7D, 0x75, 0xDF, 0x5D };
static uint8_t dmrpacket_sync_pattern_ms_sourced_voice[6] = { 0x7F, 0x7D, 0x5D, 0xD5, 0x7D, 0xFD };
static uint8_t dmrpacket_sync_pattern_ms_sourced_data[6] = { 0xD5, 0xD7, 0xF7, 0x7F, 0xD7, 0x57 };
static uint8_t dmrpacket_sync_pattern_ms_sourced_rc[6] = { 0x77, 0xD5, 0x5F, 0x7D, 0xFD, 0x77 };
static uint8_t dmrpacket_sync_pattern_direct_voice_ts1[6] = { 0x5D, 0x57, 0x7F, 0x77, 0x57, 0xFF };
static uint8_t dmrpacket_sync_pattern_direct_data_ts1[6] = { 0xF7, 0xFD, 0xD5, 0xDD, 0xFD, 0x55 };
static uint8_t dmrpacket_sync_pattern_direct_voice_ts2[6] = { 0x7D, 0xFF, 0xD5, 0xF5, 0x5D, 0x5F };
static uint8_t dmrpacket_sync_pattern_direct_data_ts2[6] = { 0xD7, 0x55, 0x7F, 0x5F, 0xF7, 0xF5 };

// Extracts the sync field of the payload (leaves out info and slot type parts).
dmrpacket_sync_bits_t *dmrpacket_sync_extract_bits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_sync_bits_t sync_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(&sync_bits.bits, payload_bits->bits+sizeof(dmrpacket_payload_info_bits_t)/2+sizeof(dmrpacket_slot_type_bits_t)/2, sizeof(sync_bits.bits));

	return &sync_bits;
}

void dmrpacket_sync_insert_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_sync_bits_t *sync_bits) {
	if (payload_bits == NULL || sync_bits == NULL)
		return;

	memcpy(payload_bits->bits+sizeof(dmrpacket_payload_info_bits_t)/2+sizeof(dmrpacket_slot_type_bits_t)/2, sync_bits->bits, sizeof(dmrpacket_sync_bits_t));
}

dmrpacket_sync_bits_t *dmrpacket_sync_construct_bits(dmrpacket_sync_pattern_type_t sync_pattern_type) {
	static dmrpacket_sync_bits_t sync_bits;

	switch (sync_pattern_type) {
		case DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE:
			base_bytestobits(dmrpacket_sync_pattern_bs_sourced_voice, sizeof(dmrpacket_sync_pattern_bs_sourced_voice),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA:
			base_bytestobits(dmrpacket_sync_pattern_bs_sourced_data, sizeof(dmrpacket_sync_pattern_bs_sourced_data),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_VOICE:
			base_bytestobits(dmrpacket_sync_pattern_ms_sourced_voice, sizeof(dmrpacket_sync_pattern_ms_sourced_voice),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_DATA:
			base_bytestobits(dmrpacket_sync_pattern_ms_sourced_data, sizeof(dmrpacket_sync_pattern_ms_sourced_data),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_RC:
			base_bytestobits(dmrpacket_sync_pattern_ms_sourced_rc, sizeof(dmrpacket_sync_pattern_ms_sourced_rc),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS1:
			base_bytestobits(dmrpacket_sync_pattern_direct_voice_ts1, sizeof(dmrpacket_sync_pattern_direct_voice_ts1),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS1:
			base_bytestobits(dmrpacket_sync_pattern_direct_data_ts1, sizeof(dmrpacket_sync_pattern_direct_data_ts1),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS2:
			base_bytestobits(dmrpacket_sync_pattern_direct_voice_ts2, sizeof(dmrpacket_sync_pattern_direct_voice_ts2),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS2:
			base_bytestobits(dmrpacket_sync_pattern_direct_data_ts2, sizeof(dmrpacket_sync_pattern_direct_data_ts2),
				sync_bits.bits, sizeof(dmrpacket_sync_bits_t));
			break;
		default:
			memset(sync_bits.bits, 0, sizeof(dmrpacket_sync_bits_t));
			break;
	}

	return &sync_bits;
}

char *dmrpacket_sync_get_readable_sync_pattern_type(dmrpacket_sync_pattern_type_t sync_pattern_type) {
	switch (sync_pattern_type) {
		default:
		case DMRPACKET_SYNC_PATTERN_TYPE_UNKNOWN: return "unknown";
		case DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE: return "bs sourced voice";
		case DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA: return "bs sourced data";
		case DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_VOICE: return "ms sourced voice";
		case DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_DATA: return "ms sourced data";
		case DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_RC: return "ms sourced rc";
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS1: return "direct voice ts1";
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS1: return "direct data ts1";
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS2: return "direct voice ts2";
		case DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS2: return "direct data ts2";
	}
}

dmrpacket_sync_pattern_type_t dmrpacket_sync_get_sync_pattern_type(dmrpacket_sync_bits_t *sync_bits) {
	uint8_t sync_bytes[6];

	base_bitstobytes(sync_bits->bits, sizeof(sync_bits->bits), sync_bytes, sizeof(sync_bytes));

	if (memcmp(sync_bytes, dmrpacket_sync_pattern_bs_sourced_voice, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_VOICE;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_bs_sourced_data, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_BS_SOURCED_DATA;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_ms_sourced_voice, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_VOICE;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_ms_sourced_data, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_DATA;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_ms_sourced_rc, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_MS_SOURCED_RC;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_direct_voice_ts1, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS1;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_direct_data_ts1, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS1;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_direct_voice_ts2, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_VOICE_TS2;
	else if (memcmp(sync_bytes, dmrpacket_sync_pattern_direct_data_ts2, sizeof(sync_bytes)) == 0)
		return DMRPACKET_SYNC_PATTERN_TYPE_DIRECT_DATA_TS2;
	else
		return DMRPACKET_SYNC_PATTERN_TYPE_UNKNOWN;
}
