#include <config/defaults.h>

#include "ttyconsole.h"
#include "tty.h"
#include "daemon-poll.h"
#include "daemon-consoleserver.h"

#include <libs/config/config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

static tty_interface_t ttyconsole = {
	.devname = NULL,
	.fd = -1,
	.speed = 0,
	.parity = 0
};

void ttyconsole_send(char *buffer, unsigned int buffer_length) {
	if (TTY_IS_CONNECTED(&ttyconsole))
		tty_send(&ttyconsole, buffer, buffer_length);
}

void ttyconsole_print(const char *format, ...) {
	char buffer[CONSOLE_INPUTBUFFERSIZE];
	size_t buffer_length = 0;
    va_list argptr;

    va_start(argptr, format);

	vsprintf(buffer, format, argptr);
	buffer_length = strlen(buffer);

	ttyconsole_send(buffer, buffer_length);

    va_end(argptr);
}

void ttyconsole_process(void) {
	char buf[CONSOLE_INPUTBUFFERSIZE];
	int j, r;

	if (config_get_ttyconsoleenabled() && daemon_poll_isfdreadable(ttyconsole.fd)) {
		r = read(ttyconsole.fd, buf, sizeof(buf));
		daemon_consoleserver_sendbroadcast(buf, r);
		for (j = 0; j < r; j++)
			console_rxbuf_add(buf[j], 0);
	}
}

void ttyconsole_init(void) {
	char *ttyconsoledevname =  NULL;

	if (config_get_ttyconsoleenabled()) {
		ttyconsoledevname = config_get_ttyconsoledev();
		console_log("ttyconsole: init, device: %s\n", ttyconsoledevname);
		tty_init(&ttyconsole, ttyconsoledevname, config_get_ttyconsolebaudrate());
		free(ttyconsoledevname);
		tty_open(&ttyconsole);
		if (TTY_IS_CONNECTED(&ttyconsole))
			daemon_poll_addfd_read(ttyconsole.fd);
	} else
		ttyconsole.fd = -1;
}

void ttyconsole_deinit(void) {
	if (config_get_ttyconsoleenabled() && TTY_IS_CONNECTED(&ttyconsole)) {
		daemon_poll_removefd(ttyconsole.fd);
		tty_close(&ttyconsole);
	}
}
