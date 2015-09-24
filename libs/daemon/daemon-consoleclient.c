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

#include DEFAULTCONFIG

#include "daemon-poll.h"
#include "daemon-consoleclient.h"
#include "console.h"

#include <libs/config/config.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static int daemon_clientsocket = -1;

void daemon_consoleclient_send(char *msg, int length) {
	if (daemon_clientsocket >= 0) {
		if (write(daemon_clientsocket, msg, length) <= 0)
			daemon_clientsocket = -1;
	}
}

flag_t daemon_consoleclient_process(void) {
	char buf[CONSOLE_INPUTBUFFERSIZE];
	int r, i;

	if (daemon_clientsocket < 0)
		return 0;

	if (!daemon_poll_isfdreadable(daemon_clientsocket))
		return 1;

	if ((r = read(daemon_clientsocket, buf, sizeof(buf)-1)) <= 0) {
		console_log("daemon: remote console disconnected\n");
		return 0;
	}

	for (i = 0; i < r; i++)
		console_rxbuf_add(buf[i], 1);

	return 1;
}

flag_t daemon_consoleclient_init(void) {
	struct sockaddr_un sunaddr;
	int res;
	char *daemonctlfile = NULL;

	if (daemon_clientsocket >= 0) {
		console_log("daemon error: already connected to remote console!\n");
		return 0;
	}

	daemonctlfile = config_get_daemonctlfile();

	daemon_clientsocket = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (daemon_clientsocket < 0) {
		free(daemonctlfile);
		return 0;
	}
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	strncpy(sunaddr.sun_path, daemonctlfile, sizeof(sunaddr.sun_path));
	free(daemonctlfile);
	res = connect(daemon_clientsocket, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		close(daemon_clientsocket);
		daemon_clientsocket = -1;
		return 0;
	}

	// Turning off buffering
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	daemon_poll_addfd_read(daemon_clientsocket);

	console_log("daemon: connected to remote console\n");
	return 1;
}

void daemon_consoleclient_deinit(void) {
	if (daemon_clientsocket >= 0) {
		shutdown(daemon_clientsocket, SHUT_RDWR);
		close(daemon_clientsocket);
		daemon_poll_removefd(daemon_clientsocket);
		daemon_clientsocket = -1;
	}
}
