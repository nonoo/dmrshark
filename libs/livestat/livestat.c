#include <config/defaults.h>

#include "livestat.h"

#include <libs/config/config.h>
#include <libs/comm/comm.h>

void livestat_process(struct ip *ip_packet, dmr_packet_t *dmr_packet) {
	if (comm_is_our_ipaddr(comm_get_ip_str(&ip_packet->ip_dst))) { // The packet is for us?
	}
}

void livestat_init(void) {
}
