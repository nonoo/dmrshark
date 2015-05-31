#include <config/defaults.h>

#include "comm.h"
#include "dmrpacket.h"
#include "snmp.h"
#include "repeaters.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>
#include <libs/base/log.h>
#include <libs/livestat/livestat.h>

#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#define _GNU_SOURCE // To get defns of NI_MAXSERV and NI_MAXHOST.
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>

static pcap_t *pcap_handle = NULL;

char *comm_get_ip_str(struct in_addr *ipaddr) {
	static char ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, ipaddr, ip, sizeof(ip));
	return ip;
}

// Retruns true if ipaddr is associated with the device we are currently listening on.
flag_t comm_is_our_ipaddr(char *ipaddr) {
	char *netdevname = NULL;
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	int i = 0;
	int res = 0;
	char dev_ipaddr[NI_MAXHOST] = {0,};

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
				console_log("livestat error: can't get IP address for interface %s: %s\n", netdevname, gai_strerror(res));
			else {
				if (strcmp(dev_ipaddr, ipaddr) == 0)
					return 1;
			}
		}
	}
	freeifaddrs(ifaddr);
	free(netdevname);
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

static void comm_processpacket(const uint8_t *packet, uint16_t length) {
	struct ether_header *eth_packet = NULL;
	struct ip *ip_packet = NULL;
	struct udphdr *udp_packet = NULL;
	int ip_header_length = 0;
	dmr_packet_t dmr_packet;

	eth_packet = (struct ether_header *)packet;
	if (ntohs(eth_packet->ether_type) != ETHERTYPE_IP) {
		console_log(LOGLEVEL_COMM_IP "  not an IP packet, dropping\n");
		return;
	}
	packet += sizeof(struct ether_header);

	ip_packet = (struct ip *)packet;
	console_log(LOGLEVEL_COMM_IP "  src: %s\n", comm_get_ip_str(&ip_packet->ip_src));
	console_log(LOGLEVEL_COMM_IP "  dst: %s\n", comm_get_ip_str(&ip_packet->ip_dst));
	ip_header_length = ip_packet->ip_hl*4; // http://www.governmentsecurity.org/forum/topic/16447-calculate-ip-size/
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
	if (length-sizeof(struct ether_header)-ip_header_length != ntohs(udp_packet->len)) {
		console_log(LOGLEVEL_COMM_IP "  udp length not equal to received packet length, dropping\n");
		return;
	}
	if (udp_packet->check != comm_calcudpchecksum(ip_packet, ip_packet->ip_hl*4, udp_packet)) {
		console_log(LOGLEVEL_COMM_IP "  udp checksum mismatch, dropping\n");
		return;
	}

	if (dmrpacket_decode(udp_packet, &dmr_packet)) {
		console_log(LOGLEVEL_COMM_DMR "comm: decoded dmr packet type: %s (0x%.2x) ts %u slot type: %s (0x%.4x) frame type: %s (0x%.4x) call type: %s (0x%.2x) dstid %u srcid %u\n",
			dmrpacket_get_readable_packet_type(dmr_packet.packet_type), dmr_packet.packet_type,
			dmr_packet.timeslot,
			dmrpacket_get_readable_slot_type(dmr_packet.slot_type), dmr_packet.slot_type,
			dmrpacket_get_readable_frame_type(dmr_packet.frame_type), dmr_packet.frame_type,
			dmrpacket_get_readable_call_type(dmr_packet.call_type), dmr_packet.call_type,
			dmr_packet.dst_id,
			dmr_packet.src_id);

		if (comm_is_our_ipaddr(comm_get_ip_str(&ip_packet->ip_dst)))
			repeaters_add(&ip_packet->ip_src);
		livestat_process(ip_packet, &dmr_packet);
	}

	if (dmrpacket_heartbeat_decode(udp_packet)) {
		if (comm_is_our_ipaddr(comm_get_ip_str(&ip_packet->ip_dst))) {
			console_log(LOGLEVEL_COMM_DMR "comm [%s]: got heartbeat\n", comm_get_ip_str(&ip_packet->ip_src));
			repeaters_add(&ip_packet->ip_src);
		}
	}
}

void comm_process(void) {
	const uint8_t *packet;
	struct pcap_pkthdr pkthdr;

	snmp_process();

	if (pcap_handle == NULL)
		return;

	packet = pcap_next(pcap_handle, &pkthdr);
	if (packet != NULL) {
		console_log(LOGLEVEL_COMM_IP "comm got packet: %u bytes\n", pkthdr.len);
		comm_processpacket(packet, pkthdr.len);
	}

	repeaters_process();
}

flag_t comm_init(void) {
	char *netdevname = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0,};
	struct bpf_program pcap_filter = {0,};
	int pcap_dev = -1;
	char *pcap_filter_str = "ip and udp";

	repeaters_init();

	netdevname = config_get_netdevicename();

	console_log("comm: opening capture device %s, capture buffer size: %u\n", netdevname, BUFSIZ);

	pcap_handle = pcap_open_live(netdevname, BUFSIZ, 1, -1, pcap_errbuf);
	if (pcap_handle == NULL) {
		console_log("comm error: couldn't open device %s: %s\n" , netdevname, pcap_errbuf);
		free(netdevname);
		return 0;
	}
	free(netdevname);
	if (pcap_compile(pcap_handle, &pcap_filter, pcap_filter_str, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		console_log("comm error: can't init packet capture: %s\n", pcap_geterr(pcap_handle));
		return 0;
	}

	if (pcap_setfilter(pcap_handle, &pcap_filter) < 0)
		console_log("comm warning: can't set filter to \"%s\"\n", pcap_filter_str);

	pcap_dev = pcap_get_selectable_fd(pcap_handle);
	if (pcap_dev == -1)
		console_log("comm warning: can't add pcap handle to the poll list\n");
	else
		daemon_poll_addfd_read(pcap_dev);

	snmp_init();

	return 1;
}

void comm_deinit(void) {
	int pcap_dev = -1;

	pcap_dev = pcap_get_selectable_fd(pcap_handle);
	if (pcap_dev > -1)
		daemon_poll_removefd(pcap_dev);

	pcap_close(pcap_handle);
	snmp_deinit();
}
