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

#include DEFAULTCONFIG

#include "userdb.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static userdb_t *userdb_first_entry = NULL;
static pthread_mutex_t userdb_mutex = PTHREAD_MUTEX_INITIALIZER;

userdb_t *userdb_get_entry_for_id(dmr_id_t id) {
	userdb_t *entry;

	pthread_mutex_lock(&userdb_mutex);
	entry = userdb_first_entry;

	while (entry) {
		if (entry->id == id) {
			pthread_mutex_unlock(&userdb_mutex);
			return entry;
		}
		entry = entry->next;
	}
	pthread_mutex_unlock(&userdb_mutex);
	return NULL;
}

char *userdb_get_display_str_for_id(dmr_id_t id) {
	userdb_t *entry = userdb_get_entry_for_id(id);
	static char result[50];

	if (entry == NULL)
		snprintf(result, sizeof(result), "%u", id);
	else
		snprintf(result, sizeof(result), "%s (%u)", entry->callsign, id);
	return result;
}

void userdb_print(void) {
	userdb_t *entry;

	pthread_mutex_lock(&userdb_mutex);
	entry = userdb_first_entry;

	if (entry == NULL) {
		console_log("userdb: empty\n");
		pthread_mutex_unlock(&userdb_mutex);
		return;
	}
	console_log("userdb:\n");
	while (entry) {
		console_log("  %6u: %s\n", entry->id, entry->callsign);
		entry = entry->next;
	}
	pthread_mutex_unlock(&userdb_mutex);
}

static void userdb_clear(void) {
	userdb_t *entry;
	userdb_t *next_entry;

	pthread_mutex_lock(&userdb_mutex);
	entry = userdb_first_entry;

	while (entry) {
		next_entry = entry->next;
		free(entry);
		entry = next_entry;
	}
	userdb_first_entry = NULL;
	pthread_mutex_unlock(&userdb_mutex);
}

// Returns 1 on success.
flag_t userdb_reload(MYSQL *remotedb_conn) {
	char *tablename = NULL;
	char query[100] = {0,};
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	userdb_t *new_entry;
	uint16_t usercount = 0;
	char *endptr;

	if (remotedb_conn == NULL)
		return 0;

	console_log(LOGLEVEL_REMOTEDB "remotedb: reloading user db\n");

	tablename = config_get_userdbtablename();
	snprintf(query, sizeof(query), "select `callsignid`, `callsign`, `name`, `country` from `%s`", tablename);
	free(tablename);

	console_log(LOGLEVEL_REMOTEDB "remotedb: sending query: %s\n", query);
	if (mysql_query(remotedb_conn, query))
		console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));

	result = mysql_store_result(remotedb_conn);
	if (result == NULL) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: can't allocate space for userdb query results\n");
		return 0;
	}

	if (mysql_num_fields(result) != 4) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: invalid returned number of fields in a row\n");
		mysql_free_result(result);
		return 0;
	}

	userdb_clear();
	pthread_mutex_lock(&userdb_mutex);
	while ((row = mysql_fetch_row(result))) {
		new_entry = (userdb_t *)calloc(1, sizeof(userdb_t));
		if (new_entry == NULL) {
			console_log(LOGLEVEL_REMOTEDB "remotedb: can't allocate memory for new user db entry\n");
			mysql_free_result(result);
			return 0;
		}
		errno = 0;
		new_entry->id = strtol(row[0], &endptr, 10);
		if (*endptr != 0 || errno != 0) {
			free(new_entry);
			continue;
		}
		strncpy(new_entry->callsign, row[1], sizeof(new_entry->callsign));
		strncpy(new_entry->name, row[1], sizeof(new_entry->name));
		strncpy(new_entry->country, row[1], sizeof(new_entry->country));

		new_entry->next = userdb_first_entry;
		userdb_first_entry = new_entry;
		usercount++;
	}
	pthread_mutex_unlock(&userdb_mutex);
	mysql_free_result(result);

	console_log(LOGLEVEL_REMOTEDB "remotedb: loaded %u users\n", usercount);
	return 1;
}

void userdb_deinit(void) {
	userdb_clear();
}
