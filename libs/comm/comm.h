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

#ifndef COMM_H_
#define COMM_H_

#include <libs/base/types.h>

#include <arpa/inet.h>

flag_t comm_hostname_to_ip(char *hostname, struct in_addr *ipaddr);
char *comm_get_ip_str(struct in_addr *ipaddr);

void comm_pcapfile_open(char *filename);

void comm_process(void);
flag_t comm_init(void);
void comm_deinit(void);

#endif
