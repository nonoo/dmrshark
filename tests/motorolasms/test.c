#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>

char *comm_get_ip_str(struct in_addr *ipaddr) {
	static char ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, ipaddr, ip, sizeof(ip));
	return ip;
}

int main(void) {
	// Full: 4500002e000c0000401158280c2110dd0c20f96d0fa70fa7001a0fca0010e00099040d000a0042004500450052000000000000000000000000000000
	// Motorola header: 0010e00099040d000a00
	uint8_t data[] = { 0x45,0x00,0x00,0x2e,0x00,0x0c,0x00,0x00,0x40,0x11,0x58,0x28,0x0c,0x21,0x10,0xdd,
						0x0c,0x20,0xf9,0x6d,0x0f,0xa7,0x0f,0xa7,0x00,0x1a,
					0x0f,0xca,0x00,0x10,0xe0,0x00,0x99,0x04,0x0d,0x00,0x0a,0x00,0x42,0x00,0x45,0x00,
					0x45,0x00,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	struct ip *ip = (struct ip *)data;
	struct udphdr *udp;
	uint16_t i;

	printf("\n\n\n");
	printf("full packet: ");
	for (i = 0; i < sizeof(data); i++)
		printf("%.2x", data[i]);
	printf("\n");
	printf("len %u (%u)\n", ntohs(ip->ip_len), sizeof(data));
	printf("hlen %u\n", ip->ip_hl);
	printf("ver %u\n", ip->ip_v);
	printf("ttl %u\n", ip->ip_ttl);
	printf("proto %u\n", ip->ip_p);
	printf("src: %s\n", comm_get_ip_str(&ip->ip_src));
	printf("dst: %s\n", comm_get_ip_str(&ip->ip_dst));

	udp = (struct udphdr *)(data+ip->ip_hl*4);
	printf("\n");
	printf("sport: %u\n", ntohs(udp->source));
	printf("dport: %u\n", ntohs(udp->dest));
	printf("ulen: %u\n", ntohs(udp->len));

	printf("payload: ");
	for (i = 0; i < ntohs(udp->len)-sizeof(struct udphdr); i++)
		printf("%.2x", data[ip->ip_hl*4+sizeof(struct udphdr)+i]);
	printf("\n");

	printf("msg: ");
	for (i = 0; i < ntohs(udp->len)-sizeof(struct udphdr); i++) {
		if (i % 2 == 0)
			printf("%c", data[ip->ip_hl*4+sizeof(struct udphdr)+10+i]);
	}
	printf("\n");

	return 0;
}
