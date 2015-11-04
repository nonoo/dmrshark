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

// To have SCM_CREDENTIALS definition in sys/socket.h
#define _GNU_SOURCE

#include "daemon-poll.h"
#include "daemon-consoleserver.h"
#include "console.h"

#include <libs/base/types.h>
#include <libs/base/log.h>
#include <libs/config/config.h>

#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>

#define MAX_CONSOLECLIENT_NUM	5

static int daemon_serversocket = -1;
typedef struct {
	int fd;		// File descriptor
	int uid;	// Remote user ID
	int gid;	// Remote group ID
} daemon_console_t;
static daemon_console_t consoles[MAX_CONSOLECLIENT_NUM];

// This is a wrapper for read() with credentials readout.
static int read_with_credentials(daemon_console_t *con, char *buffer, size_t size) {
	struct ucred cred;
	socklen_t len;
	int res;

	if ((res = read(con->fd, buffer, size)) <= 0)
		return res;

	len = sizeof(cred);
	if (getsockopt(con->fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) >= 0) {
		con->uid = cred.uid;
		con->gid = cred.gid;
	}
	return res;
}

static void daemon_consoleserver_closeconsole(int consolenum) {
	if (consoles[consolenum].fd < 0)
		return;

	shutdown(consoles[consolenum].fd, SHUT_RDWR);
	close(consoles[consolenum].fd);
	daemon_poll_removefd(consoles[consolenum].fd);
	consoles[consolenum].fd = -1;
	console_log("daemon: remote console connection #%d closed\n", consolenum);
}

void daemon_consoleserver_sendbroadcast(char *buffer, unsigned int buffer_length) {
	int i;

	if (!buffer || buffer_length == 0 || daemon_serversocket < 0)
		return;

	// Sending text to remote consoles
	for (i = 0; i < MAX_CONSOLECLIENT_NUM; i++) {
		if (consoles[i].fd < 0) // Slot not used?
			continue;

		write(consoles[i].fd, buffer, buffer_length);
	}
	// Writing text to the logfile too
	console_addtologfile(buffer, buffer_length);
}

void daemon_consoleserver_process(void) {
	socklen_t len;
	int socket = -1, sckopt, connum, j, r;
	struct sockaddr_un sunaddr;
	char buf[CONSOLE_INPUTBUFFERSIZE];

	if (daemon_serversocket < 0)
		return;

	// Do we have a new connection?
	if (daemon_poll_isfdreadable(daemon_serversocket)) {
		len = sizeof(struct sockaddr_un);
		socket = accept(daemon_serversocket, (struct sockaddr *)&sunaddr, &len);
		if (socket >= 0) {
			sckopt = 1;
			if (setsockopt(socket, SOL_SOCKET, SO_PASSCRED, &sckopt, sizeof(sckopt)) == 0) {
				for (connum = 0; connum < MAX_CONSOLECLIENT_NUM; connum++) {
					if (consoles[connum].fd >= 0) // Slot already used?
						continue;

					console_log("daemon: new remote console connection #%d\n", connum);

					consoles[connum].fd = socket;
					consoles[connum].uid = consoles[connum].gid = -2;

					daemon_poll_addfd_read(socket);
					break;
				}

				if (connum >= MAX_CONSOLECLIENT_NUM) {
					console_log("daemon error: can't accept new remote console connection\n");
					close(socket);
					socket = -1;
				} else {
					// If there was a new connection, sending stdin_buffer so the
					// user can see the currently entered command
					if (console_get_bufferpos() > 0)
						write(socket, console_get_buffer(), console_get_bufferpos());
				}
			}
		}
	}

	for (connum = 0; connum < MAX_CONSOLECLIENT_NUM; connum++) {
		if (consoles[connum].fd < 0) // Slot not used?
			continue;

		if (!daemon_poll_isfdreadable(consoles[connum].fd))
			continue;

		if ((r = read_with_credentials(&consoles[connum], buf, sizeof(buf))) <= 0) {
			daemon_consoleserver_closeconsole(connum);
			continue;
		}

		// Checking permissions
		if ((consoles[connum].uid == getuid() && consoles[connum].gid == getgid()) || consoles[connum].uid == 0) {
			daemon_consoleserver_sendbroadcast(buf, r);
			for (j = 0; j < r; j++)
				console_rxbuf_add(buf[j], 1);
		} else
			daemon_consoleserver_closeconsole(connum);
	}
}

void daemon_consoleserver_init(void) {
	struct sockaddr_un sunaddr;
	int res, i;

	char *daemonctlfile = config_get_daemonctlfile();

	for (i = 0; i < MAX_CONSOLECLIENT_NUM; i++)
		consoles[i].fd = -1;

	if (access(daemonctlfile, F_OK) >= 0) { // Control file exists?
		if (unlink(daemonctlfile) < 0) { // File exists, but can't delete?
			log_daemon_initconsoleserverfailed();
			free(daemonctlfile);
			return;
		}
	}

	// Creating the console server socket
	daemon_serversocket = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (daemon_serversocket < 0) {
		log_daemon_initconsoleserverfailed();
		free(daemonctlfile);
		return;
	}
	memset(&sunaddr, 0, sizeof(struct sockaddr_un));
	sunaddr.sun_family = AF_LOCAL;
	strncpy(sunaddr.sun_path, daemonctlfile, sizeof(sunaddr.sun_path));
	free(daemonctlfile);
	res = bind(daemon_serversocket, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		log_daemon_initconsoleserverfailed();
		close(daemon_serversocket);
		daemon_serversocket = -1;
		return;
	}

	res = listen(daemon_serversocket, MAX_CONSOLECLIENT_NUM);
	if (res < 0) {
		log_daemon_initconsoleserverfailed();
		close(daemon_serversocket);
		daemon_serversocket = -1;
		return;
	}
	daemon_poll_addfd_read(daemon_serversocket);
}

void daemon_consoleserver_deinit(void) {
	int i;

	char *daemonctlfile = config_get_daemonctlfile();

	if (daemon_serversocket >= 0) {
		for (i = 0; i < MAX_CONSOLECLIENT_NUM; i++) {
			if (consoles[i].fd == -1) // Slot not used?
				continue;
			daemon_consoleserver_closeconsole(i);
		}

		daemon_consoleserver_process(); // Write pending lines to the log
		daemon_poll_removefd(daemon_serversocket);
		close(daemon_serversocket);
		daemon_serversocket = -1;
		unlink(daemonctlfile);
	}

	free(daemonctlfile);
}
