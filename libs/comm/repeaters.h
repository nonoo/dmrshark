#ifndef REPEATERS_H_
#define REPEATERS_H_

#include <arpa/inet.h>
#include <time.h>

typedef struct {
	struct in_addr ipaddr;
	time_t last_active_time;
	time_t last_snmpinfo_request_time;
	int id;
	char type[25];
	char fwversion[25];
	char callsign[25];
	int dlfreq;
	int ulfreq;
} repeater_t;

repeater_t *repeaters_findbyip(struct in_addr *ipaddr);
void repeaters_add(struct in_addr *ipaddr);
void repeaters_process(void);
void repeaters_init(void);

#endif
