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

#ifndef DMR_HANDLE_H_
#define DMR_HANDLE_H_

#include "dmr.h"

#include <libs/comm/ipscpacket.h>
#include <libs/comm/repeaters.h>

#include <netinet/ip.h>

void dmr_handle_voicecall_end(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater);
void dmr_handle_voicecall_start(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater);
void dmr_handle_voicecall_timeout(repeater_t *repeater, dmr_timeslot_t ts);

void dmr_handle_data_timeout(repeater_t *repeater, dmr_timeslot_t ts);

void dmr_handle_voice_lc_header(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater);
void dmr_handle_terminator_with_lc(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater);
void dmr_handle_csbk(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater);
void dmr_handle_voice_frame(struct ip *ip_packet, ipscpacket_t *ipscpacket, repeater_t *repeater);

#endif
