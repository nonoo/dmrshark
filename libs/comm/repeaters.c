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
			console_log("repeaters [%s]: can't add new repeater, list is full (%u elements)\n", comm_get_ip_str(ipaddr), MAX_REPEATER_COUNT);
			return;
		}
		memset(repeater, 0, sizeof(repeater_t));
		memcpy(&repeater->ipaddr, ipaddr, sizeof(struct in_addr));
		console_log("repeaters [%s]: added\n", comm_get_ip_str(ipaddr));
	}
	repeater->last_active_time = time(NULL);
}

void repeaters_list(void) {
	int i;

	console_log("repeaters:\n");
	console_log("      nr              ip     id  callsign  act  lstinf type  fwver        dlfreq    ulfreq\n");
	for (i = 0; i < MAX_REPEATER_COUNT; i++) {
		if (repeaters[i].ipaddr.s_addr == 0)
			continue;

		console_log("  #%4u: %15s %6u %7s %4u %4u %10s %10s %9u %9u\n",
			i,
			comm_get_ip_str(&repeaters[i].ipaddr),
			repeaters[i].id,
			repeaters[i].callsign,
			time(NULL)-repeaters[i].last_active_time,
			time(NULL)-repeaters[i].last_snmpinfo_request_time,
			repeaters[i].type,
			repeaters[i].fwversion,
			repeaters[i].dlfreq,
			repeaters[i].ulfreq);
	}
}

void repeaters_process(void) {
	int i;

	for (i = 0; i < MAX_REPEATER_COUNT; i++) {
		if (repeaters[i].ipaddr.s_addr == 0)
			continue;

		if (time(NULL)-repeaters[i].last_active_time > config_get_repeaterinactivetimeoutinsec()) {
			console_log("repeaters [%s]: timed out, removing\n", comm_get_ip_str(&repeaters[i].ipaddr));
			memset(&repeaters[i], 0, sizeof(repeater_t));
			continue;
		}

		if (time(NULL)-repeaters[i].last_snmpinfo_request_time > config_get_snmpinfoupdateinsec()) {
			console_log(LOGLEVEL_DEBUG "repeaters [%s]: sending snmp info update request\n", comm_get_ip_str(&repeaters[i].ipaddr));
			snmp_start_read_repeaterinfo(comm_get_ip_str(&repeaters[i].ipaddr));
			repeaters[i].last_snmpinfo_request_time = time(NULL);
		}
	}
}

void repeaters_init(void) {
	console_log("repeaters: init\n");

	memset(&repeaters, 0, sizeof(repeater_t)*MAX_REPEATER_COUNT);
}
