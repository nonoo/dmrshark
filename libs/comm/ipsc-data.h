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

#ifndef IPSC_DATA__H_
#define IPSC_DATA__H_

#include "repeaters.h"
#include "ipscpacket.h"

#include <libs/dmrpacket/dmrpacket.h>

#include <netinet/ip.h>

void ipsc_data_handle_header(struct ip *ip_packet, ipscpacket_t *ipsc_packet, dmrpacket_payload_bits_t *packet_payload_bits, repeater_t *repeater);
void ipsc_data_handle_34rate(struct ip *ip_packet, ipscpacket_t *ipsc_packet, dmrpacket_payload_bits_t *packet_payload_bits, repeater_t *repeater);
void ipsc_data_handle_12rate(struct ip *ip_packet, ipscpacket_t *ipsc_packet, dmrpacket_payload_bits_t *packet_payload_bits, repeater_t *repeater);

#endif
