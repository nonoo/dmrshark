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

#include "comm.h"
#include "ipscpacket.h"
#include "snmp.h"
#include "repeaters.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>
#include <libs/base/log.h>
#include <libs/remotedb/remotedb.h>
#include <libs/dmrpacket/dmrpacket-data.h>
#include <libs/dmrpacket/dmrpacket-data-34rate.h>

#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#define _GNU_SOURCE // To get defns of NI_MAXSERV and NI_MAXHOST.
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>

#define HEARTBEAT_PERIOD_IN_SEC 6

static pcap_t *comm_pcap_handle = NULL;
static pcap_t *comm_pcap_file_handle = NULL;

struct __attribute__((packed)) linux_sll {
	// Packet_* describing packet origins:
	// 0 - Packet was sent to us by somebody else
	// 1 - Packet was broadcast by somebody else
	// 2 - Packet was multicast, but not broadcast, by somebody else
	// 3 - Packet was sent by somebody else to somebody else
	// 4 - Packet was sent by us
	uint16_t packet_type;
	uint16_t dev_type; // ARPHDR_* from net/if_arp.h
	uint16_t addr_len;
	uint8_t addr[8];
	uint16_t eth_type; // Same as ieee802_3 'lentype' field, with additional * Eth_Type_* exceptions
};

flag_t comm_hostname_to_ip(char *hostname, struct in_addr *ipaddr) {
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

	if ((he = gethostbyname(hostname)) == NULL)
		return 0;

	addr_list = (struct in_addr **)he->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++) {
		// Return the first one.
		memcpy(ipaddr, addr_list[i], sizeof(struct in_addr));
		return 1;
	}
	return 0;
}

char *comm_get_ip_str(struct in_addr *ipaddr) {
	static char ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, ipaddr, ip, sizeof(ip));
	return ip;
}

static char *comm_get_our_ipaddr(void) {
	char *netdevname = NULL;
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	int i = 0;
	int res = 0;
	static char dev_ipaddr[NI_MAXHOST] = {0,};

	// Finding out the IP addresses associated with the network interface we are listening on.
	netdevname = config_get_netdevicename();
	getifaddrs(&ifaddr);
	for (ifa = ifaddr, i = 0; ifa != NULL; ifa = ifa->ifa_next, i++) {
		if (ifa->ifa_addr == NULL || strcmp(netdevname, ifa->ifa_name) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
			res = getnameinfo(ifa->ifa_addr, (ifa->ifa_addr->sa_family == AF_INET) ?
				sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
				dev_ipaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (res != 0)
				console_log("comm error: can't get IP address for interface %s: %s\n", netdevname, gai_strerror(res));
			else {
				freeifaddrs(ifaddr);
				return dev_ipaddr;
			}
		}
	}
	freeifaddrs(ifaddr);
	free(netdevname);
	return NULL;
}

static flag_t comm_is_our_ipaddr(struct in_addr *ipaddr) {
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_in *addr = NULL;
	int i;

	getifaddrs(&ifaddr);
	for (ifa = ifaddr, i = 0; ifa != NULL; ifa = ifa->ifa_next, i++) {
		if (ifa->ifa_addr == NULL)
			continue;

		addr = (struct sockaddr_in *)ifa->ifa_addr;
		if (memcmp(ipaddr, &addr->sin_addr, sizeof(struct in_addr)) == 0) {
			freeifaddrs(ifaddr);
			return 1;
		}
	}
	freeifaddrs(ifaddr);
	return 0;
}

// http://www.binarytides.com/raw-udp-sockets-c-linux/
static uint16_t comm_calcipheaderchecksum(struct ip *ipheader, int ipheader_size) {
	uint8_t i;
	uint16_t nextval;
	uint32_t checksum = 0;

	for (i = 0; i < ipheader_size; i += 2) {
		if (i == 10) // Skipping CRC field.
			continue;

		if (ipheader_size-i == 1) // Last odd byte
			nextval = *(uint8_t *)((uint8_t *)ipheader+i);
		else
			nextval = *(uint16_t *)((uint8_t *)ipheader+i);

		checksum += nextval;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return ~checksum;
}

// http://www.tcpipguide.com/free/t_UDPMessageFormat-2.htm
static uint16_t comm_calcudpchecksum(struct ip *ipheader, int ipheader_size, struct udphdr *udpheader) {
	uint16_t i;
	uint8_t *u8;
	uint16_t nextval;
	uint8_t *udppayload = (uint8_t *)udpheader+sizeof(struct udphdr);
	uint32_t checksum;
	uint16_t payload_size;

	// Pseudo header
	u8 = &(((uint8_t *)&ipheader->ip_src)[0]);
	checksum = *(uint16_t *)u8;
	u8 = &(((uint8_t *)&ipheader->ip_src)[2]);
	checksum += *(uint16_t *)u8;
	u8 = &(((uint8_t *)&ipheader->ip_dst)[0]);
	checksum += *(uint16_t *)u8;
	u8 = &(((uint8_t *)&ipheader->ip_dst)[2]);
	checksum += *(uint16_t *)u8;
	checksum += htons(ipheader->ip_p);
	checksum += udpheader->len;

	// UDP header
	checksum += udpheader->source;
	checksum += udpheader->dest;
	checksum += udpheader->len;

	// UDP payload
	payload_size = ntohs(udpheader->len)-sizeof(struct udphdr);
	for (i = 0; i < payload_size; i += 2) {
		if (payload_size-i == 1) // Last odd byte
			nextval = *(uint8_t *)(udppayload+i);
		else
			nextval = *(uint16_t *)(udppayload+i);

		checksum += nextval;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return ~checksum;
}

static void comm_call_start(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM "->%s]: %s call start on ts %u src id %u dst id %u\n",
		comm_get_ip_str(&ip_packet->ip_dst), dmr_get_readable_call_type(ipsc_packet->call_type), ipsc_packet->timeslot, ipsc_packet->src_id, ipsc_packet->dst_id);
	repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_CALL_RUNNING);
	repeater->slot[ipsc_packet->timeslot-1].call_started_at = time(NULL);
	repeater->slot[ipsc_packet->timeslot-1].call_ended_at = 0;
	repeater->slot[ipsc_packet->timeslot-1].call_type = ipsc_packet->call_type;
	repeater->slot[ipsc_packet->timeslot-1].dst_id = ipsc_packet->dst_id;
	repeater->slot[ipsc_packet->timeslot-1].src_id = ipsc_packet->src_id;
	repeater->slot[ipsc_packet->timeslot-1].rssi = repeater->slot[ipsc_packet->timeslot-1].avg_rssi = 0;

	if (repeater->auto_rssi_update_enabled_at == 0 && !repeater->snmpignored) {
		console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM "->%s]: starting auto snmp rssi update\n", comm_get_ip_str(&ip_packet->ip_dst));
		repeater->auto_rssi_update_enabled_at = time(NULL)+1; // +1 - lets add a little delay to let the repeater read the correct RSSI.
	}

	remotedb_update(repeater);
}

static void comm_call_end(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING)
		return;

	console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM "->%s]: %s call end on ts %u src id %u dst id %u\n",
	comm_get_ip_str(&ip_packet->ip_dst), dmr_get_readable_call_type(ipsc_packet->call_type), ipsc_packet->timeslot, ipsc_packet->src_id, ipsc_packet->dst_id);
	repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_IDLE);
	repeater->slot[ipsc_packet->timeslot-1].call_ended_at = time(NULL);

	if (repeater->auto_rssi_update_enabled_at != 0) {
		console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM "->%s]: stopping auto rssi update\n", comm_get_ip_str(&ip_packet->ip_dst));
		repeater->auto_rssi_update_enabled_at = 0;
	}

	remotedb_update(repeater);
}

static void comm_handle_data_header(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	dmrpacket_payload_data_bits_t *packet_payload_data_bits = NULL;
	dmrpacket_data_header_t *data_packet_header = NULL;
	dmrpacket_data_header_responsetype_t data_response_type = DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;

	console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM "->%s]: got data header\n", comm_get_ip_str(&ip_packet->ip_dst));

	packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet->payload);
	packet_payload_info_bits = dmrpacket_extractinfobits(packet_payload_bits);
	packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
	dmrpacket_data_bptc_check_and_repair(packet_payload_info_bits);
	packet_payload_data_bits = dmrpacket_data_bptc_extractdata(packet_payload_info_bits);
	data_packet_header = dmrpacket_data_header_decode(packet_payload_data_bits, 0);

	repeater->slot[ipsc_packet->timeslot-1].data_blocks_received = 0;
	memset(repeater->slot[ipsc_packet->timeslot-1].data_blocks, 0, sizeof(dmrpacket_data_block_t)*sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks));
	repeater->slot[ipsc_packet->timeslot-1].data_header_received_at = time(NULL);

	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_RESPONSE) {
		data_response_type = dmrpacket_data_header_decode_response(data_packet_header);
		console_log("  response type: %s\n", dmrpacket_data_header_get_readable_response_type(data_response_type));
	}
	if (data_packet_header->common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		memcpy(&repeater->slot[ipsc_packet->timeslot-1].data_packet_header, data_packet_header, sizeof(dmrpacket_data_header_t));
		repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING);
	}
}

static void comm_handle_data_fragment_assembly_for_short_data_defined(ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_data_fragment_t *data_fragment = NULL;
	char *msg = NULL;

	// Got all blocks?
	if (repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.appended_blocks == repeater->slot[ipsc_packet->timeslot-1].data_blocks_received) {
		repeaters_state_change(repeater, ipsc_packet->timeslot-1, REPEATER_SLOT_STATE_IDLE);
		data_fragment = dmrpacket_data_extract_fragment_from_blocks(repeater->slot[ipsc_packet->timeslot-1].data_blocks,
			min(sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks)/sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks[0]), repeater->slot[ipsc_packet->timeslot-1].data_blocks_received));
		msg = dmrpacket_data_convertmsg(data_fragment, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.dd_format);
		if (msg)
			console_log("  decoded message: %s\n", msg);
	}
}

static void comm_handle_data_34rate(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	dmrpacket_data_34rate_dibits_t *packet_payload_dibits = NULL;
	dmrpacket_data_34rate_constellationpoints_t *packet_payload_constellationpoints = NULL;
	dmrpacket_data_34rate_tribits_t *packet_payload_tribits = NULL;
	dmrpacket_data_binary_t *data_binary = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING) // Data without a previously received header?
		return;

	if (repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM "->%s]: got 3/4 rate data block #%u/%u \n", comm_get_ip_str(&ip_packet->ip_dst),
			repeater->slot[ipsc_packet->timeslot-1].data_blocks_received+1, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

		packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet->payload);
		packet_payload_info_bits = dmrpacket_extractinfobits(packet_payload_bits);
		packet_payload_dibits = dmrpacket_data_34rate_extract_dibits(packet_payload_info_bits);
		packet_payload_dibits = dmrpacket_data_34rate_deinterleave_dibits(packet_payload_dibits);
		packet_payload_constellationpoints = dmrpacket_data_34rate_getconstellationpoints(packet_payload_dibits);
		packet_payload_tribits = dmrpacket_data_34rate_extract_tribits(packet_payload_constellationpoints);
		data_binary = dmrpacket_data_34rate_extract_binary(packet_payload_tribits);
		data_block_bytes = dmrpacket_data_convert_binary_to_block_bytes(data_binary);
		data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_34_DATA, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.response_requested);

		if (data_block) {
			// Storing the block if serialnr is in bounds.
			if (data_block->serialnr < sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks)/sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks[0]))
				memcpy(&repeater->slot[ipsc_packet->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
		}
		repeater->slot[ipsc_packet->timeslot-1].data_blocks_received++;

		comm_handle_data_fragment_assembly_for_short_data_defined(ipsc_packet, repeater);
	}
}

static void comm_handle_data_12rate(struct ip *ip_packet, ipscpacket_t *ipsc_packet, repeater_t *repeater) {
	dmrpacket_payload_bits_t *packet_payload_bits = NULL;
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;
	dmrpacket_payload_data_bits_t *packet_payload_data_bits = NULL;
	dmrpacket_data_block_bytes_t *data_block_bytes = NULL;
	dmrpacket_data_block_t *data_block = NULL;

	if (repeater->slot[ipsc_packet->timeslot-1].state != REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING) // Data without a previously received header?
		return;

	if (repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.data_packet_format == DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED) { // Now we only care about short data packets.
		console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM "->%s]: got 1/2 rate data block #%u/%u \n", comm_get_ip_str(&ip_packet->ip_dst),
			repeater->slot[ipsc_packet->timeslot-1].data_blocks_received+1, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.short_data_defined.appended_blocks);

		packet_payload_bits = ipscpacket_convertpayloadtobits(ipsc_packet->payload);
		packet_payload_info_bits = dmrpacket_extractinfobits(packet_payload_bits);
		packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
		dmrpacket_data_bptc_check_and_repair(packet_payload_info_bits);
		packet_payload_data_bits = dmrpacket_data_bptc_extractdata(packet_payload_info_bits);
		data_block_bytes = dmrpacket_data_convert_payload_data_bits_to_block_bytes(packet_payload_data_bits);
		data_block = dmrpacket_data_decode_block(data_block_bytes, DMRPACKET_DATA_TYPE_RATE_34_DATA, repeater->slot[ipsc_packet->timeslot-1].data_packet_header.common.response_requested);

		if (data_block) {
			// Storing the block if serialnr is in bounds.
			if (data_block->serialnr < sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks)/sizeof(repeater->slot[ipsc_packet->timeslot-1].data_blocks[0]))
				memcpy(&repeater->slot[ipsc_packet->timeslot-1].data_blocks[data_block->serialnr], data_block, sizeof(dmrpacket_data_block_t));
		}
		repeater->slot[ipsc_packet->timeslot-1].data_blocks_received++;

		comm_handle_data_fragment_assembly_for_short_data_defined(ipsc_packet, repeater);
	}
}

static void comm_processpacket(struct ip *ip_packet, uint16_t length) {
	uint8_t *packet = (uint8_t *)ip_packet;
	struct udphdr *udp_packet = NULL;
	int ip_header_length = 0;
	ipscpacket_t ipsc_packet = {0,};
	repeater_t *repeater = NULL;
	int i;
	loglevel_t loglevel = console_get_loglevel();

	if (loglevel.flags.debug && loglevel.flags.comm_ip) {
		console_log(LOGLEVEL_DEBUG "comm packet: ");
		for (i = 0; i < length; i++)
			console_log(LOGLEVEL_DEBUG "%.2x ", packet[i]);
		console_log(LOGLEVEL_DEBUG "\n");
	}

	console_log(LOGLEVEL_COMM_IP "  src: %s\n", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM_IP "  dst: %s\n", comm_get_ip_str(&ip_packet->ip_dst));
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
		console_log(LOGLEVEL_COMM_DMR "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM_DMR "->%s]: decoded dmr packet type: %s (0x%.2x) ts %u slot type: %s (0x%.4x) frame type: %s (0x%.4x) call type: %s (0x%.2x) dstid %u srcid %u\n",
			comm_get_ip_str(&ip_packet->ip_dst),
			ipscpacket_get_readable_packet_type(ipsc_packet.packet_type), ipsc_packet.packet_type,
			ipsc_packet.timeslot,
			ipscpacket_get_readable_slot_type(ipsc_packet.slot_type), ipsc_packet.slot_type,
			ipscpacket_get_readable_frame_type(ipsc_packet.frame_type), ipsc_packet.frame_type,
			dmr_get_readable_call_type(ipsc_packet.call_type), ipsc_packet.call_type,
			ipsc_packet.dst_id,
			ipsc_packet.src_id);

		// The packet is for us?
		if (comm_is_our_ipaddr(&ip_packet->ip_dst))
			repeater = repeaters_add(&ip_packet->ip_src);

		// The packet is for us, or from a listed repeater?
		if (repeater != NULL || (repeater = repeaters_findbyip(&ip_packet->ip_src)) != NULL) {
			if (repeater->slot[ipsc_packet.timeslot-1].state != REPEATER_SLOT_STATE_CALL_RUNNING && (ipsc_packet.frame_type == IPSCPACKET_FRAME_TYPE_VOICE_SYNC ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_A ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_B ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_C ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_D ||
				ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_VOICE_DATA_E))
					comm_call_start(ip_packet, &ipsc_packet, repeater);

			if (repeater->slot[ipsc_packet.timeslot-1].state == REPEATER_SLOT_STATE_CALL_RUNNING) {
				if (ipsc_packet.slot_type == IPSCPACKET_SLOT_TYPE_CALL_END)
					comm_call_end(ip_packet, &ipsc_packet, repeater);

				if (ipsc_packet.packet_type == IPSCPACKET_PACKET_TYPE_VOICE)
					repeater->slot[ipsc_packet.timeslot-1].last_packet_received_at = time(NULL);
			}

			switch (ipsc_packet.slot_type) {
				case IPSCPACKET_SLOT_TYPE_DATA_HEADER:
					comm_call_end(ip_packet, &ipsc_packet, repeater);
					comm_handle_data_header(ip_packet, &ipsc_packet, repeater);
					break;
				case IPSCPACKET_SLOT_TYPE_3_4_RATE_DATA:
					comm_call_end(ip_packet, &ipsc_packet, repeater);
					comm_handle_data_34rate(ip_packet, &ipsc_packet, repeater);
					break;
				case IPSCPACKET_SLOT_TYPE_1_2_RATE_DATA:
					comm_call_end(ip_packet, &ipsc_packet, repeater);
					comm_handle_data_12rate(ip_packet, &ipsc_packet, repeater);
					break;
				default:
					break;
			}
		}
	}

	if (ipscpacket_heartbeat_decode(udp_packet)) {
		if (comm_is_our_ipaddr(&ip_packet->ip_dst)) {
			console_log(LOGLEVEL_HEARTBEAT "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
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

void comm_pcapfile_open(char *filename) {
	char errbuf[PCAP_ERRBUF_SIZE];
	comm_pcap_file_handle = pcap_open_offline(filename, errbuf);
	int pcap_dev = -1;

	if (!comm_pcap_file_handle) {
		console_log("comm error: can't open pcap file %s: %s\n", filename, errbuf);
		return;
	}

	pcap_dev = pcap_get_selectable_fd(comm_pcap_handle);
	if (pcap_dev == -1)
		console_log("comm warning: can't add pcap file handle to the poll list\n");
	else
		daemon_poll_addfd_read(pcap_dev);

	console_log("comm: opened pcap file %s\n", filename);
}

static uint8_t *comm_get_ip_packet_from_pcap_packet(uint8_t *packet, pcap_t *pcap_handle, uint16_t *ip_packet_length) {
	struct ether_header *eth_packet = NULL;
	struct linux_sll *linux_sll_packet = NULL;

	if (pcap_datalink(pcap_handle) == pcap_datalink_name_to_val("EN10MB")) {
		eth_packet = (struct ether_header *)packet;
		if (ntohs(eth_packet->ether_type) != ETHERTYPE_IP) {
			console_log(LOGLEVEL_COMM_IP "  not an IP packet (type %u), dropping\n", ntohs(eth_packet->ether_type));
			return NULL;
		}
		*ip_packet_length -= sizeof(struct ether_header);
		packet += sizeof(struct ether_header);
	} else if (pcap_datalink(pcap_handle) == pcap_datalink_name_to_val("LINUX_SLL")) {
		linux_sll_packet = (struct linux_sll *)packet;
		if (ntohs(linux_sll_packet->eth_type) != ETHERTYPE_IP) {
			console_log(LOGLEVEL_COMM_IP "  not an IP packet (type %u), dropping\n", ntohs(linux_sll_packet->eth_type));
			return NULL;
		}
		packet += sizeof(struct linux_sll);
		*ip_packet_length -= sizeof(struct linux_sll);
	}
	return packet;
}

void comm_process(void) {
	uint8_t *packet = NULL;
	struct pcap_pkthdr pkthdr;
	uint16_t ip_packet_length = 0;
	int pcap_dev = -1;

	snmp_process();

	if (comm_pcap_handle != NULL) {
		packet = (uint8_t *)pcap_next(comm_pcap_handle, &pkthdr);
		if (packet != NULL) {
			console_log(LOGLEVEL_COMM_IP "comm got packet: %u bytes\n", pkthdr.len);
			ip_packet_length = pkthdr.len;
			packet = comm_get_ip_packet_from_pcap_packet(packet, comm_pcap_handle, &ip_packet_length);
			if (packet)
				comm_processpacket((struct ip *)packet, ip_packet_length);
		}
	}

	if (comm_pcap_file_handle != NULL) {
		packet = (uint8_t *)pcap_next(comm_pcap_file_handle, &pkthdr);
		if (packet != NULL) {
			console_log(LOGLEVEL_COMM_IP "comm got packet: %u bytes\n", pkthdr.len);
			ip_packet_length = pkthdr.len;
			packet = comm_get_ip_packet_from_pcap_packet(packet, comm_pcap_file_handle, &ip_packet_length);
			if (packet)
				comm_processpacket((struct ip *)packet, ip_packet_length);
		} else {
			console_log("comm: finished processing pcap file.\n");
			pcap_dev = pcap_get_selectable_fd(comm_pcap_file_handle);
			if (pcap_dev > -1)
				daemon_poll_removefd(pcap_dev);
			pcap_close(comm_pcap_file_handle);
			comm_pcap_file_handle = NULL;
		}
	}

	repeaters_process();
}

flag_t comm_init(void) {
	char *netdevname = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0,};
	struct bpf_program pcap_filter = {0,};
	int pcap_dev = -1;
	char *pcap_filter_str = "ip and udp";
	int *datalinks = NULL;
	int i;

	repeaters_init();

	netdevname = config_get_netdevicename();

	console_log("comm: opening capture device %s, capture buffer size: %u\n", netdevname, BUFSIZ);

	comm_pcap_handle = pcap_open_live(netdevname, BUFSIZ, 1, -1, pcap_errbuf);
	if (comm_pcap_handle == NULL) {
		console_log("comm error: couldn't open device %s: %s\n" , netdevname, pcap_errbuf);
		free(netdevname);
		return 0;
	}
	console_log("comm: dev %s ip addr is %s\n", netdevname, comm_get_our_ipaddr());
	free(netdevname);

	i = pcap_list_datalinks(comm_pcap_handle, &datalinks);
	if (i > 0) {
		pcap_set_datalink(comm_pcap_handle, datalinks[0]);
		console_log("comm: setting pcap data link to %s\n", pcap_datalink_val_to_name(datalinks[0]));
	}
	pcap_free_datalinks(datalinks);
	datalinks = NULL;

	if (pcap_compile(comm_pcap_handle, &pcap_filter, pcap_filter_str, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		console_log("comm error: can't init packet capture: %s\n", pcap_geterr(comm_pcap_handle));
		return 0;
	}

	if (pcap_setfilter(comm_pcap_handle, &pcap_filter) < 0)
		console_log("comm warning: can't set filter to \"%s\"\n", pcap_filter_str);

	pcap_dev = pcap_get_selectable_fd(comm_pcap_handle);
	if (pcap_dev == -1)
		console_log("comm warning: can't add pcap handle to the poll list\n");
	else
		daemon_poll_addfd_read(pcap_dev);

	snmp_init();

	return 1;
}

void comm_deinit(void) {
	int pcap_dev = -1;

	if (comm_pcap_handle != NULL) {
		pcap_dev = pcap_get_selectable_fd(comm_pcap_handle);
		if (pcap_dev > -1)
			daemon_poll_removefd(pcap_dev);
		pcap_close(comm_pcap_handle);
		comm_pcap_handle = NULL;
	}

	if (comm_pcap_file_handle != NULL) {
		pcap_dev = pcap_get_selectable_fd(comm_pcap_file_handle);
		if (pcap_dev > -1)
			daemon_poll_removefd(pcap_dev);
		pcap_close(comm_pcap_file_handle);
		comm_pcap_file_handle = NULL;
	}

	snmp_deinit();
}
