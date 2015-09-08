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

#ifndef DMRPACKET_EMB_H_
#define DMRPACKET_EMB_H_

#include "dmrpacket.h"

#include <libs/base/types.h>
#include <libs/base/dmr.h>

#define DMRPACKET_EMB_LCSS_SINGLE_FRAGMENT	0b00
#define DMRPACKET_EMB_LCSS_FIRST_FRAGMENT	0b01
#define DMRPACKET_EMB_LCSS_LAST_FRAGMENT	0b10
#define DMRPACKET_EMB_LCSS_CONTINUATION		0b11
typedef uint8_t dmr_lcss_t;

typedef struct {
	flag_t bits[72];
	flag_t checksum[5];
} dmrpacket_emb_signalling_lc_t;

typedef struct {
	flag_t bits[32];
} dmrpacket_emb_signalling_binary_fragment_t;

typedef struct {
	dmr_color_code_t cc;
	flag_t pi; // Privacy Indicator
	dmr_lcss_t lcss;
} dmrpacket_emb_t;

typedef struct {
	flag_t bits[16];
} dmrpacket_emb_binary_t;

dmrpacket_emb_signalling_lc_t *dmrpacket_emb_deinterleave_lc(dmrpacket_emb_signalling_lc_t *emb_signalling_lc);
flag_t dmrpacket_emb_check_checksum(dmrpacket_emb_signalling_lc_t *emb_signalling_lc);

dmrpacket_emb_signalling_binary_fragment_t *dmrpacket_emb_signalling_extract_from_sync_field(dmrpacket_payload_sync_field_bits_t *sync_field_bits);

dmrpacket_emb_t *dmrpacket_emb_decode_emb(dmrpacket_emb_binary_t *emb_binary);
dmrpacket_emb_binary_t *dmrpacket_emb_extract_from_sync_field(dmrpacket_payload_sync_field_bits_t *sync_field_bits);

#endif
