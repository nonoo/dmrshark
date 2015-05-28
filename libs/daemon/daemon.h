#ifndef DAEMON_H_
#define DAEMON_H_

#include <libs/base/types.h>

#define DAEMON_INIT_RESULT_OK					0
#define DAEMON_INIT_RESULT_FORKED_PARENTEXIT	1
#define DAEMON_INIT_RESULT_FORK_ERROR			2
#define DAEMON_INIT_RESULT_CONSOLECLIENT_ERROR	3
typedef uint8_t daemon_init_result_t;

flag_t daemon_is_consoleclient(void);
flag_t daemon_is_consoleserver(void);
flag_t daemon_is_daemonize(void);

flag_t daemon_changecwd(char *directory);
flag_t daemon_process(void);

daemon_init_result_t daemon_init(flag_t daemonize, flag_t consoleclient);
void daemon_deinit(void);

#endif