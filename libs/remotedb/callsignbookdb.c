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

#include "callsignbookdb.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static callsignbookdb_t *callsignbookdb_first_entry = NULL;
static pthread_mutex_t callsignbookdb_mutex = PTHREAD_MUTEX_INITIALIZER;

static callsignbookdb_t *callsignbookdb_get_entry_for_callsign(char *callsign) {
	callsignbookdb_t *entry;

	pthread_mutex_lock(&callsignbookdb_mutex);
	entry = callsignbookdb_first_entry;

	while (entry) {
		if (strcasecmp(entry->callsign, callsign) == 0) {
			pthread_mutex_unlock(&callsignbookdb_mutex);
			return entry;
		}
		entry = entry->next;
	}
	pthread_mutex_unlock(&callsignbookdb_mutex);
	return NULL;
}

char *callsignbookdb_get_display_str_for_callsign(char *callsign) {
	callsignbookdb_t *entry = callsignbookdb_get_entry_for_callsign(callsign);
	static char result[512];

	if (entry == NULL)
		return NULL;

	snprintf(result, sizeof(result), "%s from %s, %s %s, %s %s%s, valid %s%s%s",
		entry->name, entry->city, entry->address, entry->country, entry->type, entry->level, entry->morse ? " morse" : "", entry->validity, entry->chiefop[0] ? " chiefop " : "", entry->chiefop);
	return result;
}

void callsignbookdb_print(void) {
	callsignbookdb_t *entry;

	pthread_mutex_lock(&callsignbookdb_mutex);
	entry = callsignbookdb_first_entry;

	if (entry == NULL) {
		console_log("callsignbookdb: empty\n");
		pthread_mutex_unlock(&callsignbookdb_mutex);
		return;
	}
	console_log("callsignbookdb:\n");
	while (entry) {
		console_log("  callsign: %s name: %s country: %s city: %s addr: %s type: %s level: %s morse: %u validity: %s chiefop: %s\n",
			entry->callsign, entry->name, entry->country, entry->city, entry->address, entry->type, entry->level, entry->morse, entry->validity, entry->chiefop);
		entry = entry->next;
	}
	pthread_mutex_unlock(&callsignbookdb_mutex);
}

static void callsignbookdb_clear(void) {
	callsignbookdb_t *entry;
	callsignbookdb_t *next_entry;

	pthread_mutex_lock(&callsignbookdb_mutex);
	entry = callsignbookdb_first_entry;

	while (entry) {
		next_entry = entry->next;
		free(entry);
		entry = next_entry;
	}
	callsignbookdb_first_entry = NULL;
	pthread_mutex_unlock(&callsignbookdb_mutex);
}

// Returns 1 on success.
flag_t callsignbookdb_reload(MYSQL *remotedb_conn) {
	char *tablename = NULL;
	char query[300] = {0,};
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	callsignbookdb_t *new_entry;
	uint16_t usercount = 0;

	if (remotedb_conn == NULL)
		return 0;

	console_log(LOGLEVEL_REMOTEDB "remotedb: reloading callsign book db\n");

	tablename = config_get_callsignbookdbtablename();
	snprintf(query, sizeof(query), "select `name`, `country`, `city`, `streethouse`, `callsign`, `communityorprivate`, `levelofexam`, `morse`, `validity`, `chiefoperator` from `%s`", tablename);
	free(tablename);

	console_log(LOGLEVEL_REMOTEDB "remotedb: sending query: %s\n", query);
	if (mysql_query(remotedb_conn, query))
		console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));

	result = mysql_store_result(remotedb_conn);
	if (result == NULL) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: can't allocate space for callsignbookdb query results\n");
		return 0;
	}

	if (mysql_num_fields(result) != 10) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: invalid returned number of fields in a row\n");
		mysql_free_result(result);
		return 0;
	}

	callsignbookdb_clear();
	pthread_mutex_lock(&callsignbookdb_mutex);
	while ((row = mysql_fetch_row(result))) {
		new_entry = (callsignbookdb_t *)calloc(1, sizeof(callsignbookdb_t));
		if (new_entry == NULL) {
			console_log(LOGLEVEL_REMOTEDB "remotedb: can't allocate memory for new user db entry\n");
			mysql_free_result(result);
			return 0;
		}
		strncpy(new_entry->name, row[0], sizeof(new_entry->name));
		strncpy(new_entry->country, row[1], sizeof(new_entry->country));
		strncpy(new_entry->city, row[2], sizeof(new_entry->callsign));
		strncpy(new_entry->address, row[3], sizeof(new_entry->address));
		strncpy(new_entry->callsign, row[4], sizeof(new_entry->callsign));
		strncpy(new_entry->type, row[5], sizeof(new_entry->type));
		strncpy(new_entry->level, row[6], sizeof(new_entry->level));
		if (strlen(row[7]) > 0)
			new_entry->morse = 1;
		strncpy(new_entry->validity, row[8], sizeof(new_entry->validity));
		strncpy(new_entry->chiefop, row[9], sizeof(new_entry->chiefop));

		new_entry->next = callsignbookdb_first_entry;
		callsignbookdb_first_entry = new_entry;
		usercount++;
	}
	pthread_mutex_unlock(&callsignbookdb_mutex);
	mysql_free_result(result);

	console_log(LOGLEVEL_REMOTEDB "remotedb: loaded %u callsign book db entries\n", usercount);
	return 1;
}

void callsignbookdb_deinit(void) {
	callsignbookdb_clear();
}
