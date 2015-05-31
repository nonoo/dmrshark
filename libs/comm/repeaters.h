#ifndef REPEATERS_H_
#define REPEATERS_H_

#include <libs/base/types.h>

#include <arpa/inet.h>
#include <time.h>

typedef struct {
	struct in_addr ipaddr;
	time_t last_active_time;
	time_t last_snmpinfo_request_time;
	struct timeval last_rssi_request_time;
	int id;
	char type[25];
	char fwversion[25];
	char callsign[25];
	int dlfreq;
	int ulfreq;
	int rssi_ts1;
	int rssi_ts2;
	time_t auto_rssi_update_enabled_at;
} repeater_t;

repeater_t *repeaters_findbyip(struct in_addr *ipaddr);
flag_t repeaters_isignored(struct in_addr *ipaddr);
repeater_t *repeaters_add(struct in_addr *ipaddr);
void repeaters_list(void);

void repeaters_process(void);
void repeaters_init(void);

#endif
