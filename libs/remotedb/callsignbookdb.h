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

#ifndef CALLSIGNBOOKDB_H_
#define CALLSIGNBOOKDB_H_

#include <libs/base/dmr.h>

#include <mysql/mysql.h>

typedef struct callsignbookdb_st {
	char callsign[16];
	char name[101];
	char country[101];
	char city[101];
	char address[101];
	char type[16];
	char level[16];
	flag_t morse;
	char validity[26];
	char chiefop[101];

	struct callsignbookdb_st *next;
} callsignbookdb_t;

char *callsignbookdb_get_display_str_for_callsign(char *callsign);
void callsignbookdb_print(void);

// These are called from the remotedb process thread.
flag_t callsignbookdb_reload(MYSQL *remotedb_conn);
void callsignbookdb_deinit(void);

#endif
