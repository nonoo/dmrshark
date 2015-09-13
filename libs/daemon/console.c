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

#include <config/defaults.h>

#include "console.h"
#include "daemon.h"
#include "daemon-poll.h"
#include "daemon-consoleclient.h"
#include "daemon-consoleserver.h"
#include "ttyconsole.h"

#include <libs/base/command.h>
#include <libs/config/config.h>

#include <unistd.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#define CONSOLELOGBUFFERSIZE	CONSOLE_INPUTBUFFERSIZE
#define CONSOLE_NEWLINECHAR		'\n'

static loglevel_t loglevel = { .raw = 0xff };
static char console_buffer[CONSOLE_INPUTBUFFERSIZE] = {0,};
static uint16_t console_buffer_pos = 0;
static struct termios console_termios_save = {0,};
static flag_t console_termios_saved = 0;
static pthread_mutex_t console_mutex = PTHREAD_MUTEX_INITIALIZER;

loglevel_t console_get_loglevel(void) {
	return loglevel;
}

void console_set_loglevel(loglevel_t *new_loglevel) {
	loglevel = *new_loglevel;
}

char *console_get_buffer(void) {
	return console_buffer;
}

uint16_t console_get_bufferpos(void) {
	return console_buffer_pos;
}

void console_rxbuf_add(char inputchar, flag_t vt100supported) {
	static uint8_t skipchars = 0;

	if (inputchar == CONSOLE_NEWLINECHAR && console_buffer_pos == 0) {
		printf("\n");
		ttyconsole_send("\n", 1);
		fflush(stdin);
		return;
	}

	if (console_buffer_pos+1 == CONSOLE_INPUTBUFFERSIZE && inputchar != '\b' && inputchar != 0x7f && inputchar != CONSOLE_NEWLINECHAR)
		return;

	if (inputchar == 27) // Skipping VT100 terminal codes
		skipchars = 3;

	if (skipchars > 0) {
		skipchars--;
		return;
	}

	if (inputchar == '\b' || inputchar == 0x7f) { // 0x7f - backspace
		if (vt100supported) {
			printf("\x1b[2K\r"); // Clearing the whole line.
			ttyconsole_print("\b \b", inputchar, inputchar);
		} else {
			printf("%c %c", inputchar, inputchar);
			ttyconsole_print("%c %c", inputchar, inputchar);
		}

		if (console_buffer_pos > 0)
			console_buffer_pos--;
		console_buffer[console_buffer_pos] = 0;

		// As the line has been already cleared with the VT100 terminal code,
		// we have to print it again without the last character.
		if (vt100supported)
			printf("%s", console_buffer);
		fflush(stdout);
		return;
	}

	printf("%c", inputchar);
	ttyconsole_send(&inputchar, 1);
	fflush(stdout);

	if (inputchar == CONSOLE_NEWLINECHAR) {
		if (inputchar == '\r')
			printf("\n");
		console_buffer[console_buffer_pos] = 0;

		if (daemon_is_consoleserver())
			command_process(console_buffer);

		console_buffer_pos = 0;
	} else
		console_buffer[console_buffer_pos++] = inputchar;
}

void console_addtologfile(char *msg, int msglen) {
	static char linebuf[255] = {0,};
	static int linebufpos = 0;
	char timestamp[23] = {0,};
	int i;
	struct tm *currtm;
	time_t rawtime;
	int logfile;
	char *logfilename = NULL;

	for (i = 0; i < msglen; i++) {
		if (msg[i] == 27) { // Skipping VT100 terminal codes
			i += 3;
			if (linebufpos > 0)
				linebufpos--;
			continue;
		}
		if (msg[i] == '\b' || msg[i] == 0x7f) {
			i++;
			if (linebufpos > 0)
				linebufpos--;
			continue;
		}
		if (msg[i] == '\r') {
			linebufpos = 0;
			continue;
		}
		if (msg[i] == '\n' || linebufpos == sizeof(linebuf)) {
			time(&rawtime);
			currtm = gmtime(&rawtime);
			snprintf(timestamp, sizeof(timestamp), "[%.4d/%.2d/%.2d %.2d:%.2d:%.2d]", currtm->tm_year + 1900, currtm->tm_mon+1, currtm->tm_mday, currtm->tm_hour, currtm->tm_min, currtm->tm_sec);

			logfilename = config_get_logfilename();
			logfile = open(logfilename, O_CREAT | O_APPEND | O_WRONLY, 0664);
			free(logfilename);
			if (logfile >= 0) {
				// Adding a space if we don't have an empty line.
				if (linebufpos > 0) {
					timestamp[sizeof(timestamp)-2] = ' ';
					timestamp[sizeof(timestamp)-1] = 0;
					write(logfile, timestamp, sizeof(timestamp)-1);
				} else
					write(logfile, timestamp, sizeof(timestamp)-2);

				write(logfile, linebuf, linebufpos);
				write(logfile, "\n", 1);

				//fsync(logfile);
				close(logfile);
			}

			linebufpos = 0;
			continue;
		}

		linebuf[linebufpos++] = msg[i];
	}
}

static flag_t console_isallowedtodisplay(char loglevel_char) {
	switch (loglevel_char) {
		case LOGLEVEL_DEBUG_VAL: return loglevel.flags.debug;
		case LOGLEVEL_IPSC_VAL: return loglevel.flags.ipsc;
		case LOGLEVEL_COMM_IP_VAL: return loglevel.flags.comm_ip;
		case LOGLEVEL_COMM_DMR_VAL: return loglevel.flags.comm_dmr;
		case LOGLEVEL_SNMP_VAL: return loglevel.flags.snmp;
		case LOGLEVEL_REPEATERS_VAL: return loglevel.flags.repeaters;
		case LOGLEVEL_HEARTBEAT_VAL: return loglevel.flags.heartbeat;
		case LOGLEVEL_REMOTEDB_VAL: return loglevel.flags.remotedb;
		case LOGLEVEL_VOICESTREAMS_VAL: return loglevel.flags.voicestreams;
		default: return 1;
	}
}

static flag_t console_isloglevelchar(char loglevel_char) {
	switch (loglevel_char) {
		case LOGLEVEL_DEBUG_VAL:
		case LOGLEVEL_IPSC_VAL:
		case LOGLEVEL_COMM_IP_VAL:
		case LOGLEVEL_COMM_DMR_VAL:
		case LOGLEVEL_SNMP_VAL:
		case LOGLEVEL_REPEATERS_VAL:
		case LOGLEVEL_HEARTBEAT_VAL:
		case LOGLEVEL_REMOTEDB_VAL:
		case LOGLEVEL_VOICESTREAMS_VAL:
			return 1;
		default: return 0;
	}
}

static void console_log_display(char *text, va_list *argptr) {
	char buffer[CONSOLELOGBUFFERSIZE];
	size_t buffer_length = 0;

	pthread_mutex_lock(&console_mutex);
	vsnprintf(buffer, sizeof(buffer), text, *argptr);
	buffer_length = strlen(buffer);

	printf("%s", buffer);
	if (daemon_is_consoleserver()) {
		daemon_consoleserver_sendbroadcast(buffer, buffer_length);
		ttyconsole_send(buffer, buffer_length);
	}
	pthread_mutex_unlock(&console_mutex);
}

void console_log(char *format, ...) {
	va_list argptr;
    uint8_t first_non_format_char_pos;
    uint8_t i;

    va_start(argptr, format);

	first_non_format_char_pos = 0;
	while (console_isloglevelchar(format[first_non_format_char_pos]))
		first_non_format_char_pos++;

	for (i = 0; i < first_non_format_char_pos; i++) {
		if (!console_isallowedtodisplay(format[i]))
			return;
	}
	console_log_display(format+first_non_format_char_pos, &argptr);

    va_end(argptr);
}

void console_process(void) {
	int r, i;
	char buf[CONSOLE_INPUTBUFFERSIZE];

	// Got something from STDIN?
	if (daemon_poll_isfdreadable(STDIN_FILENO)) {
		r = read(STDIN_FILENO, buf, sizeof(buf));
		if (daemon_is_consoleclient()) {
			daemon_consoleclient_send(buf, r);
		} else {
			daemon_consoleserver_sendbroadcast(buf, r);
			for (i = 0; i < r; i++)
				console_rxbuf_add(buf[i], 1);
		}
	}
}

void console_init(void) {
	struct termios tp;

	console_log("console: init\n");

	loglevel.raw = config_get_loglevel();

	if (!daemon_is_daemonize()) {
		setvbuf(stdin, NULL, _IONBF, 0);
		if (tcgetattr(STDIN_FILENO, &tp) > -1) {
			console_termios_save = tp;
			console_termios_saved = 1;
			tp.c_lflag &= (~ICANON & ~ECHO); // Turning local echo off
			if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp) < 0)
				console_log("console error: can't set console local echo off\n");
		} else
			console_log("console error: can't set console local echo off\n");
	}

	daemon_poll_addfd_read(STDIN_FILENO);
}

void console_deinit(void) {
	console_log("console: deinit\n");

	daemon_poll_removefd(STDIN_FILENO);
	if (console_termios_saved) {
		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &console_termios_save) < 0)
			console_log("console error: can't restore console settings\n");
	}
	pthread_mutex_destroy(&console_mutex);
}
