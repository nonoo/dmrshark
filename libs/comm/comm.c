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
#include "ipsc.h"
#include "snmp.h"
#include "repeaters.h"
#include "httpserver.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>

#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#define _GNU_SOURCE // To get defns of NI_MAXSERV and NI_MAXHOST.
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>

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

	if (hostname == NULL || ipaddr == NULL)
		return 0;

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

char *comm_get_our_ipaddr(void) {
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

flag_t comm_is_our_ipaddr(struct in_addr *ipaddr) {
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_in *addr = NULL;
	int i;

	if (ipaddr == NULL)
		return 0;

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
uint16_t comm_calcipheaderchecksum(struct ip *ipheader, int ipheader_size) {
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
uint16_t comm_calcudpchecksum(struct ip *ipheader, int ipheader_size, struct udphdr *udpheader) {
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

static void comm_log_packet(uint8_t *packet, uint16_t length) {
	int i;
	loglevel_t loglevel = console_get_loglevel();

	if (loglevel.flags.debug && loglevel.flags.comm_ip) {
		console_log(LOGLEVEL_COMM_IP "comm ip packet: ");
		for (i = 0; i < length; i++)
			console_log(LOGLEVEL_COMM_IP "%.2x ", packet[i]);
		console_log(LOGLEVEL_COMM_IP "\n");
	}
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
			if (packet) {
				comm_log_packet(packet, ip_packet_length);
				ipsc_processpacket((struct ip *)packet, ip_packet_length);
			}
		}
	}

	if (comm_pcap_file_handle != NULL) {
		packet = (uint8_t *)pcap_next(comm_pcap_file_handle, &pkthdr);
		if (packet != NULL) {
			console_log(LOGLEVEL_COMM_IP "comm got packet: %u bytes\n", pkthdr.len);
			ip_packet_length = pkthdr.len;
			packet = comm_get_ip_packet_from_pcap_packet(packet, comm_pcap_file_handle, &ip_packet_length);
			if (packet) {
				comm_log_packet(packet, ip_packet_length);
				ipsc_processpacket((struct ip *)packet, ip_packet_length);
			}
		} else {
			console_log("comm: finished processing pcap file.\n");
			pcap_dev = pcap_get_selectable_fd(comm_pcap_file_handle);
			if (pcap_dev > -1)
				daemon_poll_removefd(pcap_dev);
			pcap_close(comm_pcap_file_handle);
			comm_pcap_file_handle = NULL;
		}

		// Setting timeout to 0 because select() and poll() do not work correctly on BPF devices.
		// See man pcap_get_selectable_fd for more info.
		daemon_poll_setmaxtimeout(0);
	}

	repeaters_process();
	httpserver_process();
}

flag_t comm_init(void) {
	char *netdevname = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0,};
	struct bpf_program pcap_filter = {0,};
	int pcap_dev = -1;
	char *pcap_filter_str = "ip and udp";
	int *datalinks = NULL;
	int i;

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
	httpserver_init();

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

	httpserver_deinit();
	snmp_deinit();
	repeaters_deinit();
}
