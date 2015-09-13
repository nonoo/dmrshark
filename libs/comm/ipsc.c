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

#include "ipscpacket.h"
#include "comm.h"
#include "ipsc-handle.h"

#include <libs/remotedb/remotedb.h>
#include <libs/config/config.h>
#include <libs/voicestreams/voicestreams-process.h>

#include <string.h>
#include <stdlib.h>

#define HEARTBEAT_PERIOD_IN_SEC 6

static flag_t ipsc_isignoredip(struct in_addr *ipaddr) {
	char *ignoredhosts = config_get_ignoredhosts();
	char *tok = NULL;
	struct in_addr ignoredaddr;

	tok = strtok(ignoredhosts, ",");
	if (tok) {
		do {
			if (comm_hostname_to_ip(tok, &ignoredaddr)) {
				if (memcmp(&ignoredaddr, ipaddr, sizeof(struct in_addr)) == 0) {
					free(ignoredhosts);
					return 1;
				}
			} else
				console_log(LOGLEVEL_DEBUG "repeaters: can't resolve hostname %s\n", tok);

			tok = strtok(NULL, ",");
		} while (tok != NULL);
	}
	free(ignoredhosts);
	return 0;
}

void ipsc_processpacket(struct ip *ip_packet, uint16_t length) {
	uint8_t *packet = (uint8_t *)ip_packet;
	struct udphdr *udp_packet = NULL;
	int ip_header_length = 0;
	ipscpacket_t ipsc_packet = {0,};
	repeater_t *repeater = NULL;

	console_log(LOGLEVEL_COMM_IP "  src: %s\n", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM_IP "  dst: %s\n", comm_get_ip_str(&ip_packet->ip_dst));
	if (ipsc_isignoredip(&ip_packet->ip_src)) {
		console_log(LOGLEVEL_COMM_IP "  src ip ignored, dropping\n");
		return;
	}
	ip_header_length = ip_packet->ip_hl*4; // http://www.governmentsecurity.org/forum/topic/16447-calculate-ip-size/
	console_log(LOGLEVEL_COMM_IP "  ip header length: %u\n", ip_header_length);
	if (ip_packet->ip_sum != comm_calcipheaderchecksum(ip_packet, ip_header_length)) {
		console_log(LOGLEVEL_COMM_IP "  ip checksum mismatch, dropping\n");
		return;
	}
	packet += ip_header_length;

	udp_packet = (struct udphdr *)packet;
	console_log(LOGLEVEL_COMM_IP "  srcport: %u\n", ntohs(udp_packet->source));
	console_log(LOGLEVEL_COMM_IP "  dstport: %u\n", ntohs(udp_packet->dest));
	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	console_log(LOGLEVEL_COMM_IP "  length: %u\n", ntohs(udp_packet->len)-sizeof(struct udphdr));
	if (length-ip_header_length != ntohs(udp_packet->len)) {
		console_log(LOGLEVEL_COMM_IP "  udp length not equal to received packet length, dropping\n");
		return;
	}

	if (udp_packet->check != comm_calcudpchecksum(ip_packet, ip_packet->ip_hl*4, udp_packet)) {
		console_log(LOGLEVEL_COMM_IP "  udp checksum mismatch, dropping\n");
		return;
	}

	if (ipscpacket_decode(udp_packet, &ipsc_packet)) {
		// The packet is for us?
		if (comm_is_our_ipaddr(&ip_packet->ip_dst))
			repeater = repeaters_add(&ip_packet->ip_src);

		// The packet is for us, or from a listed repeater? This is needed if dmrshark is not running on the
		// host of the DMR master, and IP packets are just routed through.
		if (repeater != NULL || (repeater = repeaters_findbyip(&ip_packet->ip_src)) != NULL) {
			console_log(LOGLEVEL_IPSC "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
			console_log(LOGLEVEL_IPSC "->%s]: decoded dmr ts %u slot type: %s (0x%.4x) call type: %s (0x%.2x) dstid %u srcid %u\n",
				comm_get_ip_str(&ip_packet->ip_dst),
				ipsc_packet.timeslot,
				ipscpacket_get_readable_slot_type(ipsc_packet.slot_type), ipsc_packet.slot_type,
				dmr_get_readable_call_type(ipsc_packet.call_type), ipsc_packet.call_type,
				ipsc_packet.dst_id,
				ipsc_packet.src_id);

			ipsc_handle(ip_packet, &ipsc_packet, repeater);
		}

		// Voice stream processing happens both for up and downlink data directions.
		if (repeater == NULL) // TODO: check if voicestreams_processpacket() works when the master sends to a repeater
			repeater = repeaters_findbyip(&ip_packet->ip_dst);
		voicestreams_processpacket(&ipsc_packet, repeater);
	}

	if (ipscpacket_heartbeat_decode(udp_packet)) {
		if (comm_is_our_ipaddr(&ip_packet->ip_dst)) {
			console_log(LOGLEVEL_HEARTBEAT "ipsc [%s", comm_get_ip_str(&ip_packet->ip_src));
			console_log(LOGLEVEL_HEARTBEAT "->%s]: got heartbeat\n", comm_get_ip_str(&ip_packet->ip_dst));
			repeater = repeaters_findbyip(&ip_packet->ip_src);
			if (repeater == NULL)
				repeater = repeaters_add(&ip_packet->ip_src);
			else if (time(NULL)-repeater->last_active_time > HEARTBEAT_PERIOD_IN_SEC/2) {
				repeater->last_active_time = time(NULL);
				remotedb_update_repeater_lastactive(repeater);
			}
		}
	}
}
