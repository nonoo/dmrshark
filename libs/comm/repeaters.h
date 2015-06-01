#ifndef REPEATERS_H_
#define REPEATERS_H_

#include "dmrpacket.h"

#include <libs/base/types.h>

#include <arpa/inet.h>
#include <time.h>

typedef struct {
	int rssi;
	flag_t call_running;
	time_t call_started_at;
	time_t last_packet_received_at;
	time_t call_ended_at;
	dmr_call_type_t call_type;
	dmr_id_t dst_id;
	dmr_id_t src_id;
} repeater_slot_t;

typedef struct {
	struct in_addr ipaddr;
	time_t last_active_time;
	flag_t snmpignored;
	time_t last_snmpinfo_request_time;
	struct timeval last_rssi_request_time;
	dmr_id_t id;
	char type[25];
	char fwversion[25];
	char callsign[25];
	int dlfreq;
	int ulfreq;
	repeater_slot_t slot[2];
	time_t auto_rssi_update_enabled_at;
} repeater_t;

repeater_t *repeaters_findbyip(struct in_addr *ipaddr);
repeater_t *repeaters_add(struct in_addr *ipaddr);
void repeaters_list(void);

void repeaters_process(void);
void repeaters_init(void);

#endif
