#ifndef DAEMON_CONSOLECLIENT_H_
#define DAEMON_CONSOLECLIENT_H_

#include <libs/base/types.h>

void daemon_consoleclient_send(char *msg, int length);

flag_t daemon_consoleclient_process(void);
flag_t daemon_consoleclient_init(void);
void daemon_consoleclient_deinit(void);

#endif
