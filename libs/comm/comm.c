#include <config/defaults.h>

#include "comm.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>

#include <pcap/pcap.h>
#include <stdlib.h>

static pcap_t *pcap_handle = NULL;

static void comm_processpacket(const uint8_t *packet, uint16_t length) {
	console_log(LOGLEVEL_DEBUG "got packet: %u bytes\n", length);
}

void comm_process(void) {
	const uint8_t *packet;
	struct pcap_pkthdr pkthdr;

	packet = pcap_next(pcap_handle, &pkthdr);
	if (packet != NULL)
		comm_processpacket(packet, pkthdr.len);
}

flag_t comm_init(void) {
	char *netdevname = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0,};
	struct bpf_program fcode = {0,};

	netdevname = config_get_netdevicename();

	console_log("comm: opening capture device %s\n", netdevname);

	pcap_handle = pcap_open_live(netdevname, BUFSIZ, 1, 0, pcap_errbuf);
	if (pcap_handle == NULL) {
		console_log("comm error: couldn't open device %s: %s\n" , netdevname, pcap_errbuf);
		free(netdevname);
		return 0;
	}
	free(netdevname);
	if (pcap_compile(pcap_handle, &fcode, "ip and udp", 1, PCAP_NETMASK_UNKNOWN) < 0) {
		console_log("comm error: can't init packet capture: %s\n", pcap_geterr(pcap_handle));
		return 0;
	}

	return 1;
}

void comm_deinit(void) {
}
