#include <config/defaults.h>

#include "tty.h"

#include <libs/base/types.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

void tty_init(tty_interface_t *ti, char *devname, int baudrate) {
	int devnamelength = strlen(devname)+1;

	if (ti == NULL || devname == NULL || strlen(devname) == 0)
		return;

	ti->devname = (char *)malloc(devnamelength);
	strncpy(ti->devname, devname, devnamelength);
	ti->devname[devnamelength-1] = 0;

	ti->fd = -1;
	switch (baudrate) {
		case 50: ti->speed = B50; break;
		case 75: ti->speed = B75; break;
		case 110: ti->speed = B110; break;
		case 134: ti->speed = B134; break;
		case 150: ti->speed = B150; break;
		case 200: ti->speed = B200; break;
		case 300: ti->speed = B300; break;
		case 600: ti->speed = B600; break;
		case 1200: ti->speed = B1200; break;
		case 1800: ti->speed = B1800; break;
		case 2400: ti->speed = B2400; break;
		case 4800: ti->speed = B4800; break;
		case 9600: ti->speed = B9600; break;
		case 19200: ti->speed = B19200; break;
		case 38400: ti->speed = B38400; break;
		case 57600: ti->speed = B57600; break;
		default:
		case 115200: ti->speed = B115200; break;
	}
	ti->parity = 0;
}

static int tty_set_attribs(tty_interface_t *ti) {
	struct termios tty;

	memset(&tty, 0, sizeof(tty));
	if (tcgetattr(ti->fd, &tty) != 0) {
		printf("tty error: %d from tcgetattr.\n", errno);
		return -1;
	}
	cfsetospeed(&tty, ti->speed);
	cfsetispeed(&tty, ti->speed);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8; // 8-bit chars
	// Disable IGNBRK for mismatched speed tests; otherwise receive break as \000 chars
	tty.c_iflag &= ~IGNBRK; // Ignore break signal
	tty.c_lflag = ECHONL; // No signaling chars, no echo
	// No canonical processing
	tty.c_oflag = 0; // No remapping, no delays
	tty.c_cc[VMIN]  = 0; // Read doesn't block
	tty.c_cc[VTIME] = 0; // Read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Shut off xon/xoff ctrl, ICRNL = Map CR to NL
	tty.c_iflag |= ICRNL;

	tty.c_cflag |= (CLOCAL | CREAD); // Ignore modem controls,
	// Enable reading
	tty.c_cflag &= ~(PARENB | PARODD); // Shut off parity
	tty.c_cflag |= ti->parity;
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS;

	if (tcsetattr(ti->fd, TCSANOW, &tty) != 0) {
		printf("tty error: %d from tcsetattr.\n", errno);
		return -1;
	}

	return 0;
}

int tty_send(tty_interface_t *ti, char *buffer, int length) {
	int i;
	int byteswritten;
	char c;

	if (!TTY_IS_CONNECTED(ti))
		return -1;

	byteswritten = 0;
	for (i = 0; i < length; i++) {
		byteswritten += write(ti->fd, &buffer[i], 1);
		usleep(300);
		if (buffer[i] == '\n') {
			c = '\r';
			byteswritten += write(ti->fd, &c, 1);
			usleep(300);
		}
	}

	if (byteswritten < length) {
		// Send error
		tty_close(ti);
		return -1;
	}
	return byteswritten;
}

void tty_open(tty_interface_t *ti) {
	ti->fd = open(ti->devname, O_RDWR | O_NOCTTY | O_SYNC);

	if (!TTY_IS_CONNECTED(ti))
		return;

	tty_set_attribs(ti);

	tcflush(ti->fd, TCIOFLUSH);
}

void tty_close(tty_interface_t *ti) {
	if (TTY_IS_CONNECTED(ti)) {
		if (ti->devname != NULL) {
			printf("tty: closing device %s\n", ti->devname);
			free(ti->devname);
		}
		close(ti->fd);
		ti->fd = -1;
	}
}
