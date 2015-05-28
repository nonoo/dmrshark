#ifndef LOG_H_
#define LOG_H_

#include <libs/daemon/console.h>

void log_ver(void);
void log_loglevel(loglevel_t *loglevel);
void log_cmdmissingparam(void);
void log_cmdinvalidparam(void);
void log_daemon_initconsoleserverfailed(void);

#endif
