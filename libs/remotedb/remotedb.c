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

#include "remotedb.h"
#include "userdb.h"
#include "callsignbookdb.h"

#include <libs/config/config.h>
#include <libs/comm/comm.h>
#include <libs/base/smstxbuf.h>

#include <stdlib.h>
#include <mysql/mysql.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define REMOTEDB_QUERYBUFSIZE	10
#define REMOTEDB_MAXQUERYSIZE	2000

typedef struct {
	char query[REMOTEDB_MAXQUERYSIZE];
} remotedb_query_t;

static pthread_mutex_t remotedb_mutex_remotedb_conn = PTHREAD_MUTEX_INITIALIZER;
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

void remotedb_add_email_to_send(char *dstemail, dmr_id_t srcid, char *msg) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};
	char *dstemail_escaped;
	char *msg_escaped;
	uint16_t dstemail_length;
	uint16_t msg_length;

	if (dstemail == NULL || msg == NULL)
		return;

	dstemail_length = strlen(dstemail);
	dstemail_escaped = (char *)calloc(1, dstemail_length*2+1);
	if (dstemail_escaped == NULL) {
		console_log("remotedb error: can't allocate memory for escaped destination email address\n");
		return;
	}
	msg_length = strlen(msg);
	msg_escaped = (char *)calloc(1, msg_length*2+1);
	if (msg_escaped == NULL) {
		console_log("remotedb error: can't allocate memory for escaped email message\n");
		free(dstemail_escaped);
		return;
	}

	pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
	mysql_real_escape_string(remotedb_conn, dstemail_escaped, dstemail, dstemail_length);
	mysql_real_escape_string(remotedb_conn, msg_escaped, msg, msg_length);
	pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "insert into `%semails-out` (`dstemail`, `srcid`, `msg`, `addedat`) values ('%s', %u, '%s', now())",
		tableprefix, dstemail_escaped, srcid, msg_escaped);
	free(tableprefix);
	free(dstemail_escaped);
	free(msg_escaped);

	remotedb_addquery(query);
}

void remotedb_add_data_to_log(repeater_t *repeater, dmr_timeslot_t ts, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, dmr_data_type_t decoded_data_type, char *decoded_data) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};
	uint16_t decoded_data_length;
	char *decoded_data_escaped = NULL;

	decoded_data_length = strlen(decoded_data);
	decoded_data_escaped = (char *)calloc(1, decoded_data_length*2+1);
	if (decoded_data_escaped == NULL) {
		console_log("remotedb error: can't allocate memory for escaped data\n");
		return;
	}
	pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
	mysql_real_escape_string(remotedb_conn, decoded_data_escaped, decoded_data, decoded_data_length);
	pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "insert into `%slog` (`repeaterid`, `srcid`, `timeslot`, `dstid`, `calltype`, `startts`, `endts`, `datatype`, `datadecoded`) "
		"values (%u, %u, %u, %u, %u, from_unixtime(%lld), from_unixtime(%lld), '%s', '%s') on duplicate key update `endts`=from_unixtime(%lld), `datatype`='%s', `datadecoded`='%s'",
		tableprefix, repeater->id, srcid, ts+1, dstid,
		calltype, (long long)repeater->slot[ts].call_started_at, (long long)repeater->slot[ts].call_ended_at,
		dmr_get_readable_data_type(decoded_data_type), decoded_data_escaped,
		(long long)repeater->slot[ts].call_ended_at, dmr_get_readable_data_type(decoded_data_type), decoded_data_escaped);
	free(tableprefix);
	free(decoded_data_escaped);

	remotedb_addquery(query);
}

static void remotedb_update_timeslot(repeater_t *repeater, dmr_timeslot_t ts) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};
	int8_t rms_vol = VOICESTREAMS_INVALID_RMS_VALUE;
	int8_t avg_rms_vol = VOICESTREAMS_INVALID_RMS_VALUE;

	if (repeater == NULL || ts > 1 || ts < 0 || repeater->slot[ts].src_id == 0 || repeater->slot[ts].dst_id == 0)
		return;

	if (remotedb_conn == NULL)
		return;

	if (repeater->slot[ts].state == REPEATER_SLOT_STATE_DATA_CALL_RUNNING)
		return;

	if (repeater->slot[ts].voicestream) {
		rms_vol = repeater->slot[ts].voicestream->rms_vol;
		avg_rms_vol = repeater->slot[ts].voicestream->avg_rms_vol;
	}

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "insert into `%slog` (`repeaterid`, `srcid`, `timeslot`, `dstid`, `calltype`, `startts`, `endts`, `currrssi`, `avgrssi`, `currrmsvol`, `avgrmsvol`) "
		"values (%u, %u, %u, %u, %u, from_unixtime(%lld), from_unixtime(%lld), %d, %d, %d, %d) on duplicate key update `endts`=from_unixtime(%lld), `currrssi`=%d, `avgrssi`=%d, `currrmsvol`=%d, `avgrmsvol`=%d",
		tableprefix, repeater->id, repeater->slot[ts].src_id, ts+1, repeater->slot[ts].dst_id,
		repeater->slot[ts].call_type, (long long)repeater->slot[ts].call_started_at, (long long)repeater->slot[ts].call_ended_at,
		repeater->slot[ts].rssi, repeater->slot[ts].avg_rssi, rms_vol, avg_rms_vol, (long long)repeater->slot[ts].call_ended_at,
		repeater->slot[ts].rssi, repeater->slot[ts].avg_rssi, rms_vol, avg_rms_vol);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_update_repeater(repeater_t *repeater) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || repeater->id == 0 || strlen(repeater->callsign) == 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "replace into `%srepeaters` (`callsign`, `id`, `type`, `fwversion`, `dlfreq`, `ulfreq`, "
		"`psuvoltage`, `patemperature`, `vswr`, `txfwdpower`, `txrefpower`, `lastactive`) "
		"values ('%s', %u, '%s', '%s', %u, %u, %f, %f, %f, %f, %f, from_unixtime(%lld))",
		tableprefix, repeater->callsign, repeater->id, repeater->type, repeater->fwversion,
		repeater->dlfreq, repeater->ulfreq, repeater->psuvoltage, repeater->patemperature,
		repeater->vswr, repeater->txfwdpower, repeater->txrefpower,
		(long long)repeater->last_active_time);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_update_repeater_lastactive(repeater_t *repeater) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || repeater->id == 0 || strlen(repeater->callsign) == 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "update `%srepeaters` set `lastactive` = from_unixtime(%lld) where `id` = %u",
		tableprefix, (long long)repeater->last_active_time, repeater->id);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_update(repeater_t *repeater) {
	remotedb_update_timeslot(repeater, 0);
	remotedb_update_timeslot(repeater, 1);
	remotedb_update_repeater_lastactive(repeater);
}

// Updates the stats table with the duration of the call.
void remotedb_update_stats_callend(repeater_t *repeater, dmr_timeslot_t ts) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};
	int talktime;

	if (repeater == NULL || !config_get_updatestatstableenabled() || ts > 1 || ts < 0)
		return;

	talktime = repeater->slot[ts].call_ended_at-repeater->slot[ts].call_started_at;

	if (talktime <= 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "insert into `%sstats` (`id`, `date`, `talktime`) "
		"values (%u, now(), %u) on duplicate key update `talktime`=`talktime`+%u",
		tableprefix, repeater->slot[ts].src_id, talktime, talktime);
	free(tableprefix);

	remotedb_addquery(query);
}

static void remotedb_thread_msgqueue_poll(void) {
	char *tableprefix = NULL;
	char query[150] = {0,};
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	dmr_id_t srcid;
	dmr_id_t dstid;
	unsigned int id;
	char *endptr;
	flag_t ids_ok;
	char msg_to_send[DMRPACKET_MAX_FRAGMENTSIZE];
	flag_t send_motorola;
	flag_t send_normal;
	smstxbuf_t *entry;

	entry = smstxbuf_get_first_entry();
	if (entry != NULL) { // Not getting new messages from the queue if smstxbuf is not empty.
		smstxbuf_free_entry(entry);
		return;
	}

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "select `index`, `srcid`, `dstid`, `msg`, `type` from `%smsg-queue` where state='waiting'", tableprefix);

	//console_log(LOGLEVEL_REMOTEDB "remotedb: sending query: %s\n", query);
	pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
	if (mysql_query(remotedb_conn, query))
		console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));
	pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);

	result = mysql_store_result(remotedb_conn);
	if (result == NULL) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: can't allocate space for userdb query results\n");
		free(tableprefix);
		return;
	}

	if (mysql_num_fields(result) != 5) {
		free(tableprefix);
		mysql_free_result(result);
		return;
	}

	while ((row = mysql_fetch_row(result))) {
		console_log("remotedb: got sms to send from msg queue\n");

		ids_ok = 1;
		errno = 0;
		srcid = strtol(row[1], &endptr, 10);
		if (errno != 0 || *endptr != 0)
			ids_ok = 0;

		errno = 0;
		dstid = strtol(row[2], &endptr, 10);
		if (errno != 0 || *endptr != 0)
			ids_ok = 0;

		errno = 0;
		id = strtol(row[0], &endptr, 10);
		if (errno != 0 || *endptr != 0)
			ids_ok = 0;

		if (ids_ok) {
			snprintf(msg_to_send, sizeof(msg_to_send), "%s: %s", userdb_get_display_str_for_id(srcid), row[3]);

			send_motorola = send_normal = 0;
			if (strcmp(row[4], "all") == 0)
				send_motorola = send_normal = 1;
			else if (strcmp(row[4], "motorola") == 0)
				send_motorola = 1;
			else if (strcmp(row[4], "normal") == 0)
				send_normal = 1;

			if (send_normal)
				smstxbuf_add(0, NULL, 0, DMR_CALL_TYPE_PRIVATE, dstid, DMR_DATA_TYPE_NORMAL_SMS, msg_to_send, id, NULL);
			if (send_motorola)
				smstxbuf_add(0, NULL, 0, DMR_CALL_TYPE_PRIVATE, dstid, DMR_DATA_TYPE_MOTOROLA_TMS_SMS, msg_to_send, id, NULL);

			snprintf(query, sizeof(query), "update `%smsg-queue` set `state`='processing' where `index`='%s'", tableprefix, row[0]);
		} else {
			console_log("  invalid src, dst id or index\n");
			snprintf(query, sizeof(query), "update `%smsg-queue` set `state`='failure' where `index`='%s'", tableprefix, row[0]);
		}

		pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
		if (mysql_query(remotedb_conn, query))
			console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));
		pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);
	}
	free(tableprefix);
	mysql_free_result(result);
}

void remotedb_msgqueue_updateentry(unsigned int db_id, flag_t success) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};

	if (!config_get_remotedbmsgqueuepollintervalinsec())
		return;

	console_log(LOGLEVEL_REMOTEDB "remotedb: updating msg queue entry id: %u success: %u\n", db_id, success);
	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "update `%smsg-queue` set `state`='%s' where `index`=%u and (`state`='processing' or `state`='failure')", tableprefix, success ? "success" : "failure", db_id);
	free(tableprefix);

	remotedb_addquery(query);
}

void remotedb_maintain(void) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};

	console_log(LOGLEVEL_REMOTEDB "remotedb: clearing log entries older than %u seconds\n", config_get_remotedbdeleteolderthansec());
	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "delete from `%slog` where unix_timestamp(`startts`) < (UNIX_TIMESTAMP() - %u) or `startts` = NULL",
		tableprefix, config_get_remotedbdeleteolderthansec());
	remotedb_addquery(query);

	if (config_get_remotedbmsgqueuepollintervalinsec()) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: clearing msg entries older than %u seconds\n", config_get_remotedbdeleteolderthansec());
		snprintf(query, sizeof(query), "delete from `%smsg-queue` where unix_timestamp(`addedat`) < (unix_timestamp() - %u)", tableprefix, config_get_remotedbdeleteolderthansec());
		remotedb_addquery(query);
	}
	free(tableprefix);
}

void remotedb_maintain_repeaterlist(void) {
	char *tableprefix = NULL;
	char query[REMOTEDB_MAXQUERYSIZE] = {0,};

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

	mysql_query(remotedb_conn, "set names 'utf8'");
	mysql_query(remotedb_conn, "set charset 'utf8'");

	free(server);
	free(user);
	free(pass);
	free(dbname);
}

static void remotedb_thread_process(void) {
	int i;
	static time_t lastconnecttriedat = 0;
	static time_t lastmaintenanceat = 0;
	static time_t lastrepeaterlistmaintenanceat = 0;
	static time_t lastuserlistqueryat = 0;
	static time_t lastcallsignbookqueryat = 0;
	static time_t lastremotedbmsgqueuepollat = 0;
	static flag_t userdb_dl_ok = 0;
	static flag_t callsignbookdb_dl_ok = 0;
	char *callsignbookdbtablename;

	if (remotedb_conn == NULL)
		return;

	if (time(NULL)-lastconnecttriedat > config_get_remotedbreconnecttrytimeoutinsec()) {
		pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
		if (mysql_ping(remotedb_conn) != 0)
			remotedb_thread_connect();
		pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);
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

	if (config_get_remotedbmsgqueuepollintervalinsec() && time(NULL)-lastremotedbmsgqueuepollat > config_get_remotedbmsgqueuepollintervalinsec()) {
		remotedb_thread_msgqueue_poll();
		lastremotedbmsgqueuepollat = time(NULL);
	}

	// If user list db download was unsuccessful, we retry it every minute.
	if (config_get_remotedbuserlistdlperiodinsec()) {
		if (time(NULL)-lastuserlistqueryat > config_get_remotedbuserlistdlperiodinsec() || (!userdb_dl_ok && time(NULL)-lastuserlistqueryat > 60)) {
			pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
			userdb_dl_ok = userdb_reload(remotedb_conn);
			pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);
			lastuserlistqueryat = time(NULL);
		}
	}

	// If callsign book db download was unsuccessful, we retry it every minute.
	if (time(NULL)-lastcallsignbookqueryat > 86400 || (!callsignbookdb_dl_ok && time(NULL)-lastcallsignbookqueryat > 60)) {
		callsignbookdbtablename = config_get_callsignbookdbtablename();
		if (callsignbookdbtablename) {
			pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
			callsignbookdb_dl_ok = callsignbookdb_reload(remotedb_conn);
			pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);
			lastcallsignbookqueryat = time(NULL);
		}
		free(callsignbookdbtablename);
	}

	// Do we have a query in the buffer?
	pthread_mutex_lock(&remotedb_mutex_querybuf);
	while (remotedb_querybuf[0].query[0] != 0) {
		console_log(LOGLEVEL_REMOTEDB "remotedb: sending query: %s\n", remotedb_querybuf[0].query);
		pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
		if (mysql_query(remotedb_conn, remotedb_querybuf[0].query))
			console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));
		pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);

		console_log(LOGLEVEL_REMOTEDB LOGLEVEL_DEBUG "remotedb: shifting the query buffer\n");
		for (i = 1; i < REMOTEDB_QUERYBUFSIZE; i++)
			strncpy(remotedb_querybuf[i-1].query, remotedb_querybuf[i].query, REMOTEDB_MAXQUERYSIZE);
		remotedb_querybuf[REMOTEDB_QUERYBUFSIZE-1].query[0] = 0;
	}
	pthread_mutex_unlock(&remotedb_mutex_querybuf);
}

static void *remotedb_thread_init(void *arg) {
	int i;
	unsigned int opt;
	struct timespec ts;

	remotedb_thread_should_stop = 0;

	for (i = 0; i < REMOTEDB_QUERYBUFSIZE; i++)
		memset(remotedb_querybuf[i].query, 0, REMOTEDB_MAXQUERYSIZE);

	pthread_cond_init(&remotedb_cond_wakeup, NULL);

	pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
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
		pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);

		while (1) {
			pthread_mutex_lock(&remotedb_mutex_thread_should_stop);
			if (remotedb_thread_should_stop) {
				pthread_mutex_unlock(&remotedb_mutex_thread_should_stop);
				break;
			}
			pthread_mutex_unlock(&remotedb_mutex_thread_should_stop);

			remotedb_thread_process();

			// If we don't have other queries in the buffer, we wait for a condition for the given timeout.
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 1;

			pthread_mutex_lock(&remotedb_mutex_wakeup);
			pthread_cond_timedwait(&remotedb_cond_wakeup, &remotedb_mutex_wakeup, &ts);
			pthread_mutex_unlock(&remotedb_mutex_wakeup);
		}

		pthread_mutex_lock(&remotedb_mutex_remotedb_conn);
		mysql_close(remotedb_conn);
		remotedb_conn = NULL;
		pthread_mutex_unlock(&remotedb_mutex_remotedb_conn);
	}

	pthread_mutex_destroy(&remotedb_mutex_remotedb_conn);
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
	} else
		console_log("remotedb: no server configured\n");
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

	userdb_deinit();
	callsignbookdb_deinit();
}
