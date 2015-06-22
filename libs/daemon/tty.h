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

#ifndef TTY_H_
#define TTY_H_

typedef struct {
	char *devname;
	int fd;
	int speed;
	int parity;
} tty_interface_t;

#define TTY_IS_CONNECTED(tty) ((tty)->fd >= 0)

void tty_init(tty_interface_t *tty, char *devname, int baudrate);
int tty_send(tty_interface_t *ti, char *buffer, int length);
void tty_open(tty_interface_t *ti);
void tty_close(tty_interface_t *ti);
int tty_read(tty_interface_t *ti);

#endif
