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

#ifndef DAEMON_CONSOLECLIENT_H_
#define DAEMON_CONSOLECLIENT_H_

#include <libs/base/types.h>

void daemon_consoleclient_send(char *msg, int length);

flag_t daemon_consoleclient_process(void);
flag_t daemon_consoleclient_init(void);
void daemon_consoleclient_deinit(void);

#endif
