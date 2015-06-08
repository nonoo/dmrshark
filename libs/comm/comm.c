#include <config/defaults.h>

#include "comm.h"
#include "dmrpacket.h"
#include "snmp.h"
#include "repeaters.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>
#include <libs/base/log.h>
#include <libs/remotedb/remotedb.h>

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

static pcap_t *pcap_handle = NULL;

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

static void comm_processpacket(const uint8_t *packet, uint16_t length) {
	struct ether_header *eth_packet = NULL;
	struct linux_sll *linux_sll_packet = NULL;
	struct ip *ip_packet = NULL;
	struct udphdr *udp_packet = NULL;
	int ip_header_length = 0;
	dmr_packet_t dmr_packet = {0,};
	repeater_t *repeater = NULL;
	loglevel_t loglevel = console_get_loglevel();
	int i;

	if (loglevel.flags.debug && loglevel.flags.comm_ip) {
		console_log(LOGLEVEL_DEBUG "comm packet: ");
		for (i = 0; i < length; i++)
			console_log(LOGLEVEL_DEBUG "%.2x ", packet[i]);
		console_log(LOGLEVEL_DEBUG "\n");
	}

	if (pcap_datalink(pcap_handle) == pcap_datalink_name_to_val("EN10MB")) {
		eth_packet = (struct ether_header *)packet;
		if (ntohs(eth_packet->ether_type) != ETHERTYPE_IP) {
			console_log(LOGLEVEL_COMM_IP "  not an IP packet (type %u), dropping\n", ntohs(eth_packet->ether_type));
			return;
		}
		packet += sizeof(struct ether_header);
	} else if (pcap_datalink(pcap_handle) == pcap_datalink_name_to_val("LINUX_SLL")) {
		linux_sll_packet = (struct linux_sll *)packet;
		if (ntohs(linux_sll_packet->eth_type) != ETHERTYPE_IP) {
			console_log(LOGLEVEL_COMM_IP "  not an IP packet (type %u), dropping\n", ntohs(linux_sll_packet->eth_type));
			return;
		}
		packet += sizeof(struct linux_sll);
	}

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
	if (pcap_datalink(pcap_handle) == pcap_datalink_name_to_val("EN10MB")) {
		if (length-sizeof(struct ether_header)-ip_header_length != ntohs(udp_packet->len)) {
			console_log(LOGLEVEL_COMM_IP "  udp length not equal to received packet length, dropping\n");
			return;
		}
	} else if (pcap_datalink(pcap_handle) == pcap_datalink_name_to_val("LINUX_SLL")) {
		if (length-sizeof(struct linux_sll)-ip_header_length != ntohs(udp_packet->len)) {
			console_log(LOGLEVEL_COMM_IP "  udp length not equal to received packet length, dropping\n");
			return;
		}
	}
	if (udp_packet->check != comm_calcudpchecksum(ip_packet, ip_packet->ip_hl*4, udp_packet)) {
		console_log(LOGLEVEL_COMM_IP "  udp checksum mismatch, dropping\n");
		return;
	}

	if (dmrpacket_decode(udp_packet, &dmr_packet)) {
		console_log(LOGLEVEL_COMM_DMR "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
		console_log(LOGLEVEL_COMM_DMR "->%s]: decoded dmr packet type: %s (0x%.2x) ts %u slot type: %s (0x%.4x) frame type: %s (0x%.4x) call type: %s (0x%.2x) dstid %u srcid %u\n",
			comm_get_ip_str(&ip_packet->ip_dst),
			dmrpacket_get_readable_packet_type(dmr_packet.packet_type), dmr_packet.packet_type,
			dmr_packet.timeslot,
			dmrpacket_get_readable_slot_type(dmr_packet.slot_type), dmr_packet.slot_type,
			dmrpacket_get_readable_frame_type(dmr_packet.frame_type), dmr_packet.frame_type,
			dmrpacket_get_readable_call_type(dmr_packet.call_type), dmr_packet.call_type,
			dmr_packet.dst_id,
			dmr_packet.src_id);

		// The packet is for us?
		if (comm_is_our_ipaddr(&ip_packet->ip_dst))
			repeater = repeaters_add(&ip_packet->ip_src);

		// The packet is for us, or from a listed repeater?
		if (repeater != NULL || (repeater = repeaters_findbyip(&ip_packet->ip_src)) != NULL) {
			if (!repeater->slot[dmr_packet.timeslot-1].call_running && dmr_packet.packet_type == DMRPACKET_PACKET_TYPE_VOICE) {
				console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
				console_log(LOGLEVEL_COMM "->%s]: %s call start on ts %u src id %u dst id %u\n",
					comm_get_ip_str(&ip_packet->ip_dst), dmrpacket_get_readable_call_type(dmr_packet.call_type), dmr_packet.timeslot, dmr_packet.src_id, dmr_packet.dst_id);
				repeater->slot[dmr_packet.timeslot-1].call_running = 1;
				repeater->slot[dmr_packet.timeslot-1].call_started_at = time(NULL);
				repeater->slot[dmr_packet.timeslot-1].call_ended_at = 0;
				repeater->slot[dmr_packet.timeslot-1].call_type = dmr_packet.call_type;
				repeater->slot[dmr_packet.timeslot-1].dst_id = dmr_packet.dst_id;
				repeater->slot[dmr_packet.timeslot-1].src_id = dmr_packet.src_id;

				if (repeater->auto_rssi_update_enabled_at == 0 && !repeater->snmpignored) {
					console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
					console_log(LOGLEVEL_COMM "->%s]: starting auto snmp rssi update\n", comm_get_ip_str(&ip_packet->ip_dst));
					repeater->auto_rssi_update_enabled_at = time(NULL)+1; // +1 - lets add a little delay to let the repeater read the correct RSSI.
				}

				remotedb_update(repeater);
			}

			if (repeater->slot[dmr_packet.timeslot-1].call_running && dmr_packet.slot_type == DMRPACKET_SLOT_TYPE_CALL_END) {
				console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
				console_log(LOGLEVEL_COMM "->%s]: %s call end on ts %u src id %u dst id %u\n",
					comm_get_ip_str(&ip_packet->ip_dst), dmrpacket_get_readable_call_type(dmr_packet.call_type), dmr_packet.timeslot, dmr_packet.src_id, dmr_packet.dst_id);
				repeater->slot[dmr_packet.timeslot-1].call_running = 0;
				repeater->slot[dmr_packet.timeslot-1].call_ended_at = time(NULL);

				if (repeater->auto_rssi_update_enabled_at != 0) {
					console_log(LOGLEVEL_COMM "comm [%s", comm_get_ip_str(&ip_packet->ip_src));
					console_log(LOGLEVEL_COMM "->%s]: stopping auto rssi update\n", comm_get_ip_str(&ip_packet->ip_dst));
					repeater->auto_rssi_update_enabled_at = 0;
				}

				remotedb_update(repeater);
			}

			if (repeater->slot[dmr_packet.timeslot-1].call_running && dmr_packet.packet_type == DMRPACKET_PACKET_TYPE_VOICE)
				repeater->slot[dmr_packet.timeslot-1].last_packet_received_at = time(NULL);
		}
	}

	if (dmrpacket_heartbeat_decode(udp_packet)) {
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
	int *datalinks = NULL;
	int i;

	repeaters_init();

	netdevname = config_get_netdevicename();

	console_log("comm: opening capture device %s, capture buffer size: %u\n", netdevname, BUFSIZ);

	pcap_handle = pcap_open_live(netdevname, BUFSIZ, 1, -1, pcap_errbuf);
	if (pcap_handle == NULL) {
		console_log("comm error: couldn't open device %s: %s\n" , netdevname, pcap_errbuf);
		free(netdevname);
		return 0;
	}
	console_log("comm: dev %s ip addr is %s\n", netdevname, comm_get_our_ipaddr());
	free(netdevname);

	i = pcap_list_datalinks(pcap_handle, &datalinks);
	if (i > 0) {
		pcap_set_datalink(pcap_handle, datalinks[0]);
		console_log("comm: setting pcap data link to %s\n", pcap_datalink_val_to_name(datalinks[0]));
	}
	pcap_free_datalinks(datalinks);
	datalinks = NULL;

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
