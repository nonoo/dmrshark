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

#ifndef DMRPACKET_LC_H_
#define DMRPACKET_LC_H_

#include "dmrpacket-types.h"
#include "dmrpacket-emb.h"

#include <libs/base/dmr.h>
#include <libs/coding/bptc-196-96.h>

typedef struct {
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
} dmrpacket_lc_t;

dmrpacket_lc_t *dmrpacket_lc_decode_emb_signalling_lc(dmrpacket_emb_signalling_lc_bits_t *deinterleaved_emb_signalling_lc_bits);
void dmrpacket_lc_insert_emb_signalling_lc_fragment_bits(dmrpacket_payload_bits_t *payload_bits, dmrpacket_emb_signalling_lc_fragment_bits_t *emb_signalling_lc_fragment_bits);
dmrpacket_emb_signalling_lc_bits_t *dmrpacket_lc_construct_emb_signalling_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id);

dmrpacket_lc_t *dmrpacket_lc_decode_voice_lc_header(bptc_196_96_data_bits_t *data_bits);
dmrpacket_lc_t *dmrpacket_lc_decode_terminator_with_lc(bptc_196_96_data_bits_t *data_bits);

bptc_196_96_data_bits_t *dmrpacket_lc_construct_voice_lc_header(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id);
bptc_196_96_data_bits_t *dmrpacket_lc_construct_terminator_with_lc(dmr_call_type_t call_type, dmr_id_t dst_id, dmr_id_t src_id);

#endif
