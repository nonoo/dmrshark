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

#include "daemon-poll.h"

#include <stdlib.h>
#include <stdio.h>

static struct pollfd *pfd = NULL; // This stores the watched file descriptors as pollfd structures.
static int pfdcount = 0; // How much pollfd structures we store.
static int polltimeout = 0;

static int daemon_poll_pfdrealloc(int count) {
	struct pollfd *newpfd;

	if (count <= 0) {
		free(pfd);
		pfd = NULL;
		return 1;
	}

	newpfd = (struct pollfd *)realloc(pfd, sizeof(struct pollfd) * count);
	if (!newpfd)
		return 0;

	pfd = newpfd;
	return 1;
}

static int daemon_poll_getpfdindex(int fd) {
	int i;

	for (i = 0; i < pfdcount; i++) {
		if (pfd[i].fd == fd)
			return i;
	}
	return -1;
}

void daemon_poll_addfd(int fd, short events) {
	int i = daemon_poll_getpfdindex(fd);

	if (i >= 0) { // If we already watch the fd, we update the watched events
		pfd[i].events |= events;
		pfd[i].revents = 0;
		return;
	}

	if (!daemon_poll_pfdrealloc(pfdcount+1))
		return;

	pfd[pfdcount].fd = fd;
	pfd[pfdcount].events = events;
	pfd[pfdcount].revents = 0;
	pfdcount++;
}

void daemon_poll_addfd_read(int fd) {
	daemon_poll_addfd(fd, POLLIN);
}

void daemon_poll_addfd_write(int fd) {
	daemon_poll_addfd(fd, POLLOUT);
}

void daemon_poll_addfd_readwrite(int fd) {
	daemon_poll_addfd(fd, POLLIN | POLLOUT);
}

void daemon_poll_changefd(int fd, short events) {
	int i = daemon_poll_getpfdindex(fd);

	if (i >= 0) {
		pfd[i].events = events;
//		pfd[i].revents = 0;
	}
}

void daemon_poll_removefd(int fd) {
	int i, found = 0;

	if (pfdcount <= 0)
		return;

	// Searching for the fd
	for (i = 0; i < pfdcount-1; i++) {
		if (pfd[i].fd == fd)
			found = 1;
		// If the item was found, we shift the other ones to the left
		if (found)
			pfd[i] = pfd[i+1];
	}

	if (pfd[pfdcount-1].fd == fd)
		found = 1;

	if (found) {
		pfdcount--;
		daemon_poll_pfdrealloc(pfdcount);
	}
}

void daemon_poll_setmaxtimeout(int timeout) {
	if (timeout < polltimeout)
		polltimeout = timeout;
}

int daemon_poll_isfdreadable(int fd) {
	int i = daemon_poll_getpfdindex(fd);

	if (i < 0)
		return 0;

	return ((pfd[i].revents & POLLIN) > 0);
}

int daemon_poll_isfdwritable(int fd) {
	int i = daemon_poll_getpfdindex(fd);

	if (i < 0)
		return 0;

	return ((pfd[i].revents & POLLOUT) > 0);
}

struct pollfd *daemon_poll_getpfd(void) {
	return pfd;
}

int daemon_poll_getpfdcount(void) {
	return pfdcount;
}

void daemon_poll_process(void) {
	poll(pfd, pfdcount, polltimeout);

	// Setting a default poll timeout, this can be overridden once at a time by daemon_poll_setmaxtimeout()
	polltimeout = 1000;
}

void daemon_poll_init(void) {
	pfdcount = 0;
}

void daemon_poll_deinit(void) {
	if (pfd)
		free(pfd);
	pfd = NULL;
	pfdcount = 0;
}
