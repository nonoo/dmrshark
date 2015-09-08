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

#ifndef DMRLOG_H_
#define DMRLOG_H_

#include <libs/comm/ipscpacket.h>
#include <libs/comm/repeaters.h>

#include <netinet/ip.h>

void dmrlog_voicecall_end(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater);
void dmrlog_voicecall_start(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater);

#endif
