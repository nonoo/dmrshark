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

#ifndef LOG_H_
#define LOG_H_

#include <libs/daemon/console.h>

#include <netinet/in.h>

void log_ver(void);
void log_loglevel(loglevel_t *loglevel);
void log_cmdmissingparam(void);
void log_cmdinvalidparam(void);
void log_daemon_initconsoleserverfailed(void);
void log_print_separator(void);

#endif
