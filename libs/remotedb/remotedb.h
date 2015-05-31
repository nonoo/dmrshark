#ifndef REMOTEDB_H_
#define REMOTEDB_H_

#include <libs/comm/dmrpacket.h>
#include <libs/comm/repeaters.h>

#include <netinet/ip.h>

void remotedb_call_start_cb(repeater_t *repeater, uint8_t timeslot);
void remotedb_call_end_cb(repeater_t *repeater, uint8_t timeslot);

void remotedb_init(void);
void remotedb_deinit(void);

#endif
