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

#include "dmrpacket.h"

#include <string.h>

// Extracts the info part of the payload (leaves out slot type and sync parts).
dmrpacket_payload_info_bits_t *dmrpacket_extractinfobits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_payload_info_bits_t info_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(&info_bits.bits, payload_bits->bits, sizeof(info_bits.bits)/2);
	memcpy(&info_bits.bits[sizeof(info_bits.bits)/2], payload_bits->bits+98+10+48+10, sizeof(info_bits.bits)/2);

	return &info_bits;
}

// Extracts the slot type part of the payload (leaves out info and sync parts).
dmrpacket_payload_slot_type_bits_t *dmrpacket_extractslottypebits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_payload_slot_type_bits_t slot_type_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(&slot_type_bits.bits, payload_bits->bits+98, sizeof(slot_type_bits.bits)/2);
	memcpy(&slot_type_bits.bits[sizeof(slot_type_bits.bits)/2], payload_bits->bits+98+10+48, sizeof(slot_type_bits.bits)/2);

	return &slot_type_bits;
}

// Extracts the sync part of the payload (leaves out info and slot type parts).
dmrpacket_payload_sync_bits_t *dmrpacket_extractsyncbits(dmrpacket_payload_bits_t *payload_bits) {
	static dmrpacket_payload_sync_bits_t sync_bits;

	if (payload_bits == NULL)
		return NULL;

	memcpy(&sync_bits.bits, payload_bits->bits+98+10, sizeof(sync_bits.bits));

	return &sync_bits;
}
