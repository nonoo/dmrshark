#ifndef CONSOLE_H_
#define CONSOLE_H_

#include <libs/base/types.h>

#define LOGLEVEL_DEBUG			"\x01"
#define LOGLEVEL_DEBUG_VAL		0x01

// Don't forget to add new loglevels to the log command handler in command.c,
// and to the loglevel display list in log.c!
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		uint8_t debug			: 1;
	} flags;
	uint8_t raw;
} loglevel_t;

char *console_get_buffer(void);
uint16_t console_get_bufferpos(void);

void console_rxbuf_add(char inputchar, flag_t vt100supported);

void console_addtologfile(char *msg, int msglen);
void console_log(const char *format, ...);

void console_process(void);
void console_init(void);
void console_deinit(void);

#endif
