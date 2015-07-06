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

#ifndef REMOTEDB_H_
#define REMOTEDB_H_

#include <libs/comm/repeaters.h>

#include <netinet/ip.h>

void remotedb_update_repeater(repeater_t *repeater);
void remotedb_update_repeater_lastactive(repeater_t *repeater);

void remotedb_update(repeater_t *repeater);
void remotedb_update_stats_callend(repeater_t *repeater, dmr_timeslot_t timeslot);
void remotedb_maintain(void);
void remotedb_maintain_repeaterlist(void);

void remotedb_init(void);
void remotedb_deinit(void);

#endif
