#ifndef REMOTEDB_H_
#define REMOTEDB_H_

#include <libs/comm/dmrpacket.h>
#include <libs/comm/repeaters.h>

#include <netinet/ip.h>

void remotedb_update(repeater_t *repeater);
void remotedb_maintain(void);

void remotedb_process(void);
void remotedb_init(void);
void remotedb_deinit(void);

#endif
