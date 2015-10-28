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

#include "ipsc.h"
#include "comm.h"
#include "ipsc-handle.h"
#include "snmp.h"

#include <libs/remotedb/remotedb.h>
#include <libs/config/config.h>
#include <libs/base/log.h>

#include <string.h>
#include <stdlib.h>

#define HEARTBEAT_PERIOD_IN_SEC 6

static flag_t ipsc_isignoredip(struct in_addr *ipaddr) {
	char *ignoredhosts = config_get_ignoredhosts();
	char *tok = NULL;
	struct in_addr ignoredaddr;

	if (ignoredhosts == NULL)
		return 0;

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

static flag_t ipsc_isignoredtalkgroup(dmr_id_t id) {
	char *allowedtgs = config_get_allowedtalkgroups();
	char *ignoredtgs = config_get_ignoredtalkgroups();
	char *tok = NULL;
	int tg;
	char *endptr;

	if (ignoredtgs == NULL)
		return 0;
	if (allowedtgs != NULL) {
		tok = strtok(allowedtgs, ",");
		if (tok) {
			do {
				if (*tok == '*')
					return 0;

				errno = 0;
				tg = strtol(tok, &endptr, 10);
				if (*endptr == 0 && errno == 0) {
					if (tg == id) {
						free(allowedtgs);
						return 0;
					}
				} else
					console_log(LOGLEVEL_DEBUG "ipsc: invalid allowed talk group %s\n", tok);

				tok = strtok(NULL, ",");
			} while (tok != NULL);
		}
		free(allowedtgs);
	}

	if (ignoredtgs != NULL) {
		tok = strtok(ignoredtgs, ",");
		if (tok) {
			do {
				if (*tok == '*')
					return 1;

				errno = 0;
				tg = strtol(tok, &endptr, 10);
				if (*endptr == 0 && errno == 0) {
					if (tg == id) {
						free(ignoredtgs);
						return 1;
					}
				} else
					console_log(LOGLEVEL_DEBUG "ipsc: invalid ignored talk group %s\n", tok);

				tok = strtok(NULL, ",");
			} while (tok != NULL);
		}
		free(ignoredtgs);
	}
	return 0;
}

static void ipsc_examinepacket(struct ip *ip_packet, ipscpacket_t *ipscpacket, flag_t packet_from_us) {
	flag_t talkgroup_ignored = 0;
	flag_t duplicate_seqnum = 0;
	flag_t call_already_running = 0;
	repeater_t *repeater = NULL;
	loglevel_t loglevel;

	repeater = repeaters_add(&ip_packet->ip_src);
	if (repeater == NULL)
		return;

	if (repeaters_is_call_running_on_other_repeater(repeater, ipscpacket->timeslot-1, ipscpacket->src_id))
		call_already_running = 1;

	if (ipscpacket->call_type == DMR_CALL_TYPE_GROUP && ipsc_isignoredtalkgroup(ipscpacket->dst_id))
		talkgroup_ignored = 1;

	// IPSC syncs have seqnum 0 so we don't check their duplicateness.
	if (ipscpacket->seq == repeater->slot[ipscpacket->timeslot-1].ipsc_last_received_seqnum && ipscpacket->slot_type != IPSCPACKET_SLOT_TYPE_IPSC_SYNC)
		duplicate_seqnum = 1;
	else
		repeater->slot[ipscpacket->timeslot-1].ipsc_last_received_seqnum = ipscpacket->seq;

	loglevel = console_get_loglevel();
	if (!loglevel.flags.comm_ip && !loglevel.flags.debug && !loglevel.flags.dmrlc && loglevel.flags.ipsc)
		log_print_separator();

	console_log(LOGLEVEL_IPSC "ipsc [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_IPSC "->%s]: dmr packet ts %u ipsc slot type: %s (0x%.4x) call type: %s (0x%.2x) dstid %u srcid %u",
		repeaters_get_display_string_for_ip(&ip_packet->ip_dst),
		ipscpacket->timeslot,
		ipscpacket_get_readable_slot_type(ipscpacket->slot_type), ipscpacket->slot_type,
		dmr_get_readable_call_type(ipscpacket->call_type), ipscpacket->call_type,
		ipscpacket->dst_id,
		ipscpacket->src_id);

	if (duplicate_seqnum)
		console_log(LOGLEVEL_IPSC " (duplicate, ignored)");
	if (talkgroup_ignored)
		console_log(LOGLEVEL_IPSC " (talkgroup ignored)");
	if (call_already_running)
		console_log(LOGLEVEL_IPSC " (call already running, ignored)");

	console_log(LOGLEVEL_IPSC "\n");
	if (!duplicate_seqnum && !talkgroup_ignored && !call_already_running)
		ipsc_handle_by_slot_type(ip_packet, ipscpacket, repeater);
}

void ipsc_processpacket(ipscpacket_raw_t *ipscpacket_raw, uint16_t length) {
	struct ip *ip_packet = (struct ip *)ipscpacket_raw->bytes;
	struct udphdr *udp_packet = NULL;
	int ip_header_length = 0;
	ipscpacket_t ipscpacket = {0,};
	repeater_t *repeater = NULL;
	flag_t packet_from_us = 0;
	loglevel_t loglevel = console_get_loglevel();

	if (!loglevel.flags.ipsc && !loglevel.flags.debug && !loglevel.flags.dmrlc && loglevel.flags.comm_ip)
		log_print_separator();

	console_log(LOGLEVEL_COMM_IP "  src: %s\n", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM_IP "  dst: %s\n", repeaters_get_display_string_for_ip(&ip_packet->ip_dst));
	if (ipsc_isignoredip(&ip_packet->ip_src)) {
		console_log(LOGLEVEL_COMM_IP "  src ip ignored, dropping\n");
		return;
	}
	ip_header_length = ip_packet->ip_hl*4; // http://www.governmentsecurity.org/forum/topic/16447-calculate-ip-size/
	console_log(LOGLEVEL_COMM_IP "  ip header length: %u\n", ip_header_length);
	if (ip_packet->ip_sum != comm_calcipheaderchecksum(ip_packet)) {
		console_log(LOGLEVEL_COMM_IP "  ip checksum mismatch, dropping\n");
		return;
	}

	udp_packet = (struct udphdr *)(ipscpacket_raw->bytes + ip_header_length);
	if (ntohs(ip_packet->ip_len) != ip_header_length+ntohs(udp_packet->len)) {
		console_log(LOGLEVEL_COMM_IP "  ip length (%u) and udp length (%u+%u) mismatch, dropping\n", ntohs(ip_packet->ip_len), ip_header_length+ntohs(udp_packet->len));
		return;
	}
	console_log(LOGLEVEL_COMM_IP "  srcport: %u\n", ntohs(udp_packet->source));
	console_log(LOGLEVEL_COMM_IP "  dstport: %u\n", ntohs(udp_packet->dest));
	// Length in UDP header contains length of the UDP header too, so we are substracting it.
	console_log(LOGLEVEL_COMM_IP "  length: %u\n", ntohs(udp_packet->len)-sizeof(struct udphdr));
	if (length-ip_header_length != ntohs(udp_packet->len)) {
		console_log(LOGLEVEL_COMM_IP "  udp length not equal to received packet length, dropping\n");
		return;
	}

	if (!comm_is_our_ipaddr(&ip_packet->ip_src) && udp_packet->check != comm_calcudpchecksum(ip_packet, udp_packet)) {
		console_log(LOGLEVEL_COMM_IP "  udp checksum mismatch, dropping\n");
		return;
	}

	packet_from_us = comm_is_our_ipaddr(&ip_packet->ip_src);
	if (ipscpacket_decode(ip_packet, udp_packet, &ipscpacket, packet_from_us))
		ipsc_examinepacket(ip_packet, &ipscpacket, packet_from_us);

	if (ipscpacket_heartbeat_decode(udp_packet)) {
		if (comm_is_our_ipaddr(&ip_packet->ip_dst)) {
			console_log(LOGLEVEL_HEARTBEAT "ipsc [%s", repeaters_get_display_string_for_ip(&ip_packet->ip_src));
			console_log(LOGLEVEL_HEARTBEAT "->%s]: got heartbeat\n", repeaters_get_display_string_for_ip(&ip_packet->ip_dst));
			repeater = repeaters_add(&ip_packet->ip_src);
			if (repeater != NULL && !repeater->snmpignored) {
				remotedb_update_repeater_lastactive(repeater);
				snmp_start_read_repeaterstatus(comm_get_ip_str(&repeater->ipaddr));
			}
		}
	}
}

void ipsc_init(void) {
	struct in_addr *masterip;
	repeater_t *repeater;

	masterip = config_get_masteripaddr();
	repeater = repeaters_add(masterip);
	if (repeater == NULL)
		console_log("ipsc init error: can't add the master's ip to the repeaters list\n");
	else
		repeater->snmpignored = 1;
	free(masterip);
}
