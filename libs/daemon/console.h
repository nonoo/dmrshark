/*
 * This file is part of dmrshark.
 *
 * dmrshark is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dmrshark is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dmrshark.  If not, see <http://www.gnu.org/licenses/>.
**/

#ifndef CONSOLE_H_
#define CONSOLE_H_

#include <libs/base/types.h>

#define LOGLEVEL_DEBUG			"\x01"
#define LOGLEVEL_DEBUG_VAL		0x01
#define LOGLEVEL_IPSC			"\x02"
#define LOGLEVEL_IPSC_VAL		0x02
#define LOGLEVEL_COMM_IP		"\x03"
#define LOGLEVEL_COMM_IP_VAL	0x03
#define LOGLEVEL_COMM_DMR		"\x04"
#define LOGLEVEL_COMM_DMR_VAL	0x04
#define LOGLEVEL_SNMP			"\x05"
#define LOGLEVEL_SNMP_VAL		0x05
#define LOGLEVEL_REPEATERS		"\x06"
#define LOGLEVEL_REPEATERS_VAL	0x06
#define LOGLEVEL_HEARTBEAT		"\x07"
#define LOGLEVEL_HEARTBEAT_VAL	0x07
#define LOGLEVEL_REMOTEDB		"\x08"
#define LOGLEVEL_REMOTEDB_VAL	0x08

// Don't forget to add new loglevels to the log command handler in command.c,
// and to the loglevel display list in log.c!
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		uint8_t debug			: 1;
		uint8_t ipsc			: 1;
		uint8_t comm_ip			: 1;
		uint8_t comm_dmr		: 1;
		uint8_t snmp			: 1;
		uint8_t repeaters		: 1;
		uint8_t heartbeat		: 1;
		uint8_t remotedb		: 1;
	} flags;
	uint8_t raw;
} loglevel_t;

loglevel_t console_get_loglevel(void);
void console_set_loglevel(loglevel_t *new_loglevel);
char *console_get_buffer(void);
uint16_t console_get_bufferpos(void);

void console_rxbuf_add(char inputchar, flag_t vt100supported);

void console_addtologfile(char *msg, int msglen);
void console_log(const char *format, ...);

void console_process(void);
void console_init(void);
void console_deinit(void);

#endif
