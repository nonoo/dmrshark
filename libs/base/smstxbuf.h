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

#ifndef SMSTXBUF_H_
#define SMSTXBUF_H_

#include "dmr.h"

#include <libs/dmrpacket/dmrpacket-data.h>

#include <time.h>

void smstxbuf_print(void);
void smstxbuf_add(dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid, char *msg);

void smstxbuf_process(void);
void smstxbuf_deinit(void);

#endif
