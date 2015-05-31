#ifndef COMM_H_
#define COMM_H_

#include <libs/base/types.h>

#include <arpa/inet.h>

char *comm_get_ip_str(struct in_addr *ipaddr);
flag_t comm_is_our_ipaddr(char *ipaddr);

void comm_process(void);
flag_t comm_init(void);
void comm_deinit(void);

#endif
