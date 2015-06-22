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

#ifndef DAEMON_H_
#define DAEMON_H_

#include <libs/base/types.h>

#define DAEMON_INIT_RESULT_OK					0
#define DAEMON_INIT_RESULT_FORKED_PARENTEXIT	1
#define DAEMON_INIT_RESULT_FORK_ERROR			2
#define DAEMON_INIT_RESULT_CONSOLECLIENT_ERROR	3
typedef uint8_t daemon_init_result_t;

flag_t daemon_is_consoleclient(void);
flag_t daemon_is_consoleserver(void);
flag_t daemon_is_daemonize(void);

flag_t daemon_changecwd(char *directory);
flag_t daemon_process(void);

daemon_init_result_t daemon_init(flag_t daemonize, flag_t consoleclient);
void daemon_deinit(void);

#endif