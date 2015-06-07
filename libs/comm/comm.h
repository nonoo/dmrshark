#ifndef COMM_H_
#define COMM_H_

#include <libs/base/types.h>

#include <arpa/inet.h>

flag_t comm_hostname_to_ip(char *hostname, struct in_addr *ipaddr);
char *comm_get_ip_str(struct in_addr *ipaddr);

void comm_process(void);
flag_t comm_init(void);
void comm_deinit(void);

#endif
