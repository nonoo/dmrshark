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

#ifndef USERDB_H_
#define USERDB_H_

#include <libs/base/dmr.h>

#include <mysql/mysql.h>

typedef struct userdb_st {
	dmr_id_t id;
	char callsign[8];
	char name[20];
	char country[20];

	struct userdb_st *next;
} userdb_t;

userdb_t *userdb_get_entry_for_id(dmr_id_t id);
char *userdb_get_display_str_for_id(dmr_id_t id);
void userdb_print(void);

// These are called from the remotedb process thread.
flag_t userdb_reload(MYSQL *remotedb_conn);
void userdb_deinit(void);

#endif
