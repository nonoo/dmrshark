#ifndef LIVESTAT_H_
#define LIVESTAT_H_

#include <libs/comm/dmrpacket.h>

#include <netinet/ip.h>

void livestat_process(struct ip *ip_packet, dmr_packet_t *dmr_packet);
void livestat_init(void);

#endif
