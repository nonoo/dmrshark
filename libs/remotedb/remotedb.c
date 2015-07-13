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

#include <config/defaults.h>

#include "remotedb.h"

#include <libs/config/config.h>
#include <libs/comm/comm.h>

#include <stdlib.h>
#include <mysql/mysql.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define REMOTEDB_QUERYBUFSIZE	10
#define REMOTEDB_MAXQUERYSIZE	1024

typedef struct {
	char query[REMOTEDB_MAXQUERYSIZE];
} remotedb_query_t;

static MYSQL *remotedb_conn = NULL;
static pthread_t remotedb_thread;

static pthread_mutex_t remotedb_mutex_thread_should_stop = PTHREAD_MUTEX_INITIALIZER;
static flag_t remotedb_thread_should_stop = 0;

static pthread_mutex_t remotedb_mutex_querybuf = PTHREAD_MUTEX_INITIALIZER;
static remotedb_query_t remotedb_querybuf[REMOTEDB_QUERYBUFSIZE];

static pthread_mutex_t remotedb_mutex_wakeup = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t remotedb_cond_wakeup;

static void remotedb_addquery(char *query) {
	int i;

	if (query == NULL)
		return;

	pthread_mutex_lock(&remotedb_mutex_querybuf);
	for (i = 0; i < REMOTEDB_QUERYBUFSIZE; i++) {
		if (remotedb_querybuf[i].query[0] == 0) {
			strncpy(remotedb_querybuf[i].query, query, REMOTEDB_MAXQUERYSIZE);
			//console_log(LOGLEVEL_REMOTEDB "remotedb: added query to buf entry #%u: %s\n", i, query);

			pthread_mutex_unlock(&remotedb_mutex_querybuf);

			// Waking up the thread if it's sleeping.
			pthread_mutex_lock(&remotedb_mutex_wakeup);
			pthread_cond_signal(&remotedb_cond_wakeup);
			pthread_mutex_unlock(&remotedb_mutex_wakeup);
			return;
		}
	}
	pthread_mutex_unlock(&remotedb_mutex_querybuf);
}

static void remotedb_update_timeslot(repeater_t *repeater, dmr_timeslot_t timeslot) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	if (repeater == NULL || timeslot > 2 || timeslot < 1 || repeater->slot[timeslot-1].src_id == 0 || repeater->slot[timeslot-1].dst_id == 0)
		return;

	if (remotedb_conn == NULL)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "replace into `%slog` (`repeaterid`, `srcid`, `timeslot`, `dstid`, `calltype`, `startts`, `endts`, `currrssi`, `avgrssi`) "
		"values (%u, %u, %u, %u, %u, from_unixtime(%lld), from_unixtime(%lld), %d, %d)",
		tableprefix, repeater->id, repeater->slot[timeslot-1].src_id, timeslot, repeater->slot[timeslot-1].dst_id,
		repeater->slot[timeslot-1].call_type, (long long)repeater->slot[timeslot-1].call_started_at, (long long)repeater->slot[timeslot-1].call_ended_at,
		repeater->slot[timeslot-1].rssi, repeater->slot[timeslot-1].avg_rssi);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_update_repeater(repeater_t *repeater) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || repeater->id == 0 || strlen(repeater->callsign) == 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "replace into `%srepeaters` (`callsign`, `id`, `type`, `fwversion`, `dlfreq`, `ulfreq`, `lastactive`) "
		"values ('%s', %u, '%s', '%s', %u, %u, from_unixtime(%lld))",
		tableprefix, repeater->callsign, repeater->id, repeater->type, repeater->fwversion,
		repeater->dlfreq, repeater->ulfreq, (long long)repeater->last_active_time);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_update_repeater_lastactive(repeater_t *repeater) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || repeater->id == 0 || strlen(repeater->callsign) == 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "update `%srepeaters` set `lastactive` = from_unixtime(%lld) where `id` = %u",
		tableprefix, (long long)repeater->last_active_time, repeater->id);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_update(repeater_t *repeater) {
	remotedb_update_timeslot(repeater, 1);
	remotedb_update_timeslot(repeater, 2);
	remotedb_update_repeater_lastactive(repeater);
}

// Updates the stats table with the duration of the call.
void remotedb_update_stats_callend(repeater_t *repeater, dmr_timeslot_t timeslot) {
	char *tableprefix = NULL;
	char query[512] = {0,};
	int talktime;

	if (repeater == NULL || !config_get_updatestatstableenabled() || timeslot > 2 || timeslot < 1)
		return;

	talktime = repeater->slot[timeslot-1].call_ended_at-repeater->slot[timeslot-1].call_started_at;

	if (talktime <= 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "insert into `%sstats` (`id`, `date`, `talktime`) "
		"values (%u, now(), %u) on duplicate key update `talktime`=`talktime`+%u",
		tableprefix, repeater->slot[timeslot-1].src_id, talktime, talktime);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_maintain(void) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	console_log(LOGLEVEL_REMOTEDB "remotedb: clearing entries older than %u seconds\n", config_get_remotedbdeleteolderthansec());
	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "delete from `%slog` where unix_timestamp(`startts`) < (UNIX_TIMESTAMP() - %u) or `startts` = NULL",
		tableprefix, config_get_remotedbdeleteolderthansec());
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_maintain_repeaterlist(void) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	console_log(LOGLEVEL_REMOTEDB "remotedb: clearing repeater entries older than %u seconds\n", config_get_repeaterinactivetimeoutinsec());
	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "delete from `%srepeaters` where unix_timestamp(`lastactive`) < (UNIX_TIMESTAMP() - %u) or `lastactive` = NULL",
		tableprefix, config_get_repeaterinactivetimeoutinsec());
	free(tableprefix);

	remotedb_addquery(query);
}

static void remotedb_thread_connect(void) {
	char *server = NULL;
	char *user = NULL;
	char *pass = NULL;
	char *dbname = NULL;

	server = config_get_remotedbhost();
	user = config_get_remotedbuser();
	pass = config_get_remotedbpass();
	dbname = config_get_remotedbname();

	console_log("remotedb: trying to connect to mysql server %s...\n", server);
	if (!mysql_real_connect(remotedb_conn, server, user, pass, dbname, 0, NULL, CLIENT_REMEMBER_OPTIONS))
		console_log("remotedb error: can't connect to remote db: %s\n", mysql_error(remotedb_conn));
	else
		console_log("remotedb: connected\n");

	free(server);
	free(user);
	free(pass);
	free(dbname);
}

// Returns 1 if we have another query in the query buffer (so we should not sleep at all).
static flag_t remotedb_thread_process(void) {
	int i;
	static time_t lastconnecttriedat = 0;
	static time_t lastmaintenanceat = 0;
	static time_t lastrepeaterlistmaintenanceat = 0;
	flag_t query_left_in_buffer = 0;

	if (remotedb_conn == NULL)
		return 0;

	if (time(NULL)-lastconnecttriedat > config_get_remotedbreconnecttrytimeoutinsec()) {
		if (mysql_ping(remotedb_conn) != 0)
			remotedb_thread_connect();
		lastconnecttriedat = time(NULL);
	}

	if (config_get_remotedbmaintenanceperiodinsec() > 0 && time(NULL)-lastmaintenanceat > config_get_remotedbmaintenanceperiodinsec()) {
		remotedb_maintain();
		lastmaintenanceat = time(NULL);
	}

	if (time(NULL)-lastrepeaterlistmaintenanceat > config_get_repeaterinactivetimeoutinsec()) {
		remotedb_maintain_repeaterlist();
		lastrepeaterlistmaintenanceat = time(NULL);
	}

	// Do we have a query in the buffer?
	pthread_mutex_lock(&remotedb_mutex_querybuf);
	if (remotedb_querybuf[0].query[0] != 0) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: sending query: %s\n", remotedb_querybuf[0].query);
		if (mysql_query(remotedb_conn, remotedb_querybuf[0].query))
			console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));

		console_log(LOGLEVEL_REMOTEDB "remotedb: shifting the query buffer\n");
		for (i = 1; i < REMOTEDB_QUERYBUFSIZE; i++)
			strncpy(remotedb_querybuf[i-1].query, remotedb_querybuf[i].query, REMOTEDB_MAXQUERYSIZE);
		remotedb_querybuf[REMOTEDB_QUERYBUFSIZE-1].query[0] = 0;

		query_left_in_buffer = (remotedb_querybuf[0].query[0] != 0);
		console_log(LOGLEVEL_REMOTEDB "remotedb: query left in buffer: %u\n", query_left_in_buffer);
	}
	pthread_mutex_unlock(&remotedb_mutex_querybuf);

	return query_left_in_buffer;
}

static void *remotedb_thread_init(void *arg) {
	int i;
	unsigned int opt;
	struct timespec ts;

	remotedb_thread_should_stop = 0;

	for (i = 0; i < REMOTEDB_QUERYBUFSIZE; i++)
		memset(remotedb_querybuf[i].query, 0, REMOTEDB_MAXQUERYSIZE);

	pthread_cond_init(&remotedb_cond_wakeup, NULL);

	remotedb_conn = mysql_init(NULL);
	if (remotedb_conn == NULL)
		console_log("remotedb error: can't initialize mysql\n");
	else {
		opt = 3;
		mysql_options(remotedb_conn, MYSQL_OPT_CONNECT_TIMEOUT, &opt);
		opt = 3;
		mysql_options(remotedb_conn, MYSQL_OPT_WRITE_TIMEOUT, &opt);
		opt = 3;
		mysql_options(remotedb_conn, MYSQL_OPT_READ_TIMEOUT, &opt);

		remotedb_thread_connect();

		while (1) {
			pthread_mutex_lock(&remotedb_mutex_thread_should_stop);
			if (remotedb_thread_should_stop) {
				pthread_mutex_unlock(&remotedb_mutex_thread_should_stop);
				break;
			}
			pthread_mutex_unlock(&remotedb_mutex_thread_should_stop);

			if (!remotedb_thread_process()) {
				// If we don't have other queries in the buffer, we wait for a condition for the given timeout.
				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_sec += 1;

				pthread_mutex_lock(&remotedb_mutex_wakeup);
				pthread_cond_timedwait(&remotedb_cond_wakeup, &remotedb_mutex_wakeup, &ts);
				pthread_mutex_unlock(&remotedb_mutex_wakeup);
			}
		}

		mysql_close(remotedb_conn);
		remotedb_conn = NULL;
	}

	pthread_mutex_destroy(&remotedb_mutex_thread_should_stop);
	pthread_mutex_destroy(&remotedb_mutex_querybuf);
	pthread_mutex_destroy(&remotedb_mutex_wakeup);
	pthread_cond_destroy(&remotedb_cond_wakeup);

	pthread_exit((void*) 0);
}

void remotedb_init(void) {
	pthread_attr_t attr;
	char *server = NULL;

	console_log("remotedb: init\n");

	server = config_get_remotedbhost();
	if (strlen(server) != 0) {
		console_log("remotedb: starting thread for remote db\n");

		// Explicitly creating the thread as joinable to be compatible with other systems.
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		pthread_create(&remotedb_thread, &attr, remotedb_thread_init, NULL);
	}
	free(server);
}

void remotedb_deinit(void) {
	void *status = NULL;

	console_log("remotedb: deinit\n");

	// Waking up the thread if it's sleeping.
	pthread_mutex_lock(&remotedb_mutex_wakeup);
	pthread_cond_signal(&remotedb_cond_wakeup);
	pthread_mutex_unlock(&remotedb_mutex_wakeup);

	pthread_mutex_lock(&remotedb_mutex_thread_should_stop);
	remotedb_thread_should_stop = 1;
	pthread_mutex_unlock(&remotedb_mutex_thread_should_stop);
	console_log("remotedb: waiting for remote db thread to exit\n");
	pthread_join(remotedb_thread, &status);
}
