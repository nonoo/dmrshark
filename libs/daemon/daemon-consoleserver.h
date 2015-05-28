#ifndef DAEMON_CONSOLESERVER_H_
#define DAEMON_CONSOLESERVER_H_

void daemon_consoleserver_sendbroadcast(char *buffer, unsigned int buffer_length);

void daemon_consoleserver_process(void);

void daemon_consoleserver_init(void);
void daemon_consoleserver_deinit(void);

#endif
