#include <config/defaults.h>

#include "repeaters.h"
#include "comm.h"
#include "snmp.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>

#include <string.h>

static repeater_t repeaters[MAX_REPEATER_COUNT];

repeater_t *repeaters_findbyip(struct in_addr *ipaddr) {
	int i;

	for (i = 0; i < MAX_REPEATER_COUNT; i++) {
		if (memcmp(&repeaters[i].ipaddr, ipaddr, sizeof(struct in_addr)) == 0)
			return &repeaters[i];
	}
	return NULL;
}

static repeater_t *repeaters_findfirstemptyslot(void) {
	int i;

	for (i = 0; i < MAX_REPEATER_COUNT; i++) {
		if (repeaters[i].ipaddr.s_addr == 0)
			return &repeaters[i];
	}
	return NULL;
}

void repeaters_add(struct in_addr *ipaddr) {
	repeater_t *repeater = repeaters_findbyip(ipaddr);

	if (repeater == NULL) {
		repeater = repeaters_findfirstemptyslot();
		if (repeater == NULL) {
			console_log("repeaters: can't add new repeater, list is full (%u elements)\n", MAX_REPEATER_COUNT);
			return;
		}
		memset(repeater, 0, sizeof(repeater_t));
		memcpy(&repeater->ipaddr, ipaddr, sizeof(struct in_addr));
		console_log("repeaters: added repeater with ip %s\n", comm_get_ip_str(ipaddr));
	}
	repeater->last_active_time = time(NULL);
}

void repeaters_process(void) {
	int i;

	for (i = 0; i < MAX_REPEATER_COUNT; i++) {
		if (repeaters[i].ipaddr.s_addr == 0)
			continue;

		if (time(NULL)-repeaters[i].last_active_time > config_get_repeaterinactivetimeoutinsec()) {
			console_log("repeaters: timed out, removing ip %s\n", comm_get_ip_str(&repeaters[i].ipaddr));
			memset(&repeaters[i], 0, sizeof(repeater_t));
			continue;
		}

		if (time(NULL)-repeaters[i].last_snmpinfo_request_time > config_get_snmpinfoupdateinsec()) {
			console_log(LOGLEVEL_DEBUG "repeaters: sending snmp info update request to ip %s\n", comm_get_ip_str(&repeaters[i].ipaddr));
			snmp_start_read_repeaterinfo(comm_get_ip_str(&repeaters[i].ipaddr));
			repeaters[i].last_snmpinfo_request_time = time(NULL);
		}
	}
}

void repeaters_init(void) {
	memset(&repeaters, 0, sizeof(repeater_t)*MAX_REPEATER_COUNT);
}
