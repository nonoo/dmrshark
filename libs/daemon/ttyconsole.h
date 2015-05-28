#ifndef TTYCONSOLE_H_
#define TTYCONSOLE_H_

void ttyconsole_send(char *buffer, unsigned int buffer_length);
void ttyconsole_print(const char *format, ...);

void ttyconsole_process(void);
void ttyconsole_init(void);
void ttyconsole_deinit(void);

#endif
