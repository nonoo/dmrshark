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
