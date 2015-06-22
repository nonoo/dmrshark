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

#ifndef DAEMON_POLL_H_
#define DAEMON_POLL_H_

#include <sys/poll.h>

// This function adds the given file descriptor to the watched file descriptor list.
// Events represents the events we need to watch on this fd (see "man poll").
void daemon_poll_addfd(int fd, short events);
// These functions are wrappers for daemon_poll_addfd()
void daemon_poll_addfd_read(int fd);
void daemon_poll_addfd_write(int fd);
void daemon_poll_addfd_readwrite(int fd);
void daemon_poll_changefd(int fd, short events);
// This function removes the given file descriptor from the watched file descriptor list.
void daemon_poll_removefd(int fd);
// This function sets the maximum timeout the poll() call will wait if no events happen on
// the watched file descriptors. The timeout will be reseted to a default value after the
// poll() call.
void daemon_poll_setmaxtimeout(int timeout);
// These functions query the result of the poll() call for the given file descriptor.
int daemon_poll_isfdreadable(int fd);
int daemon_poll_isfdwritable(int fd);

struct pollfd *daemon_poll_getpfd(void);
int daemon_poll_getpfdcount(void);

void daemon_poll_process(void);
void daemon_poll_init(void);
void daemon_poll_deinit(void);

#endif
