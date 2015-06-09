#include <config/defaults.h>

#include "remotedb.h"

#include <libs/config/config.h>
#include <libs/comm/comm.h>

#include <stdlib.h>
#include <mysql/mysql.h>
#include <string.h>
#include <stdio.h>

static MYSQL *remotedb_conn = NULL;

static void remotedb_query(char *query) {
	if (remotedb_conn == NULL || query == NULL)
		return;

	console_log(LOGLEVEL_REMOTEDB "remotedb: sending query: %s\n", query);
	if (mysql_query(remotedb_conn, query)) {
		console_log(LOGLEVEL_REMOTEDB "remotedb error: %s\n", mysql_error(remotedb_conn));
		return;
	}
}

static void remotedb_update_timeslot(repeater_t *repeater, dmr_timeslot_t timeslot) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	if (repeater == NULL || repeater->slot[timeslot-1].src_id == 0 || repeater->slot[timeslot-1].dst_id == 0)
		return;

	if (remotedb_conn == NULL)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "replace into `%slive` (`repeaterid`, `srcid`, `timeslot`, `dstid`, `calltype`, `startts`, `endts`, `currrssi`, `avgrssi`) "
		"values (%u, %u, %u, %u, %u, from_unixtime(%lld), from_unixtime(%lld), %d, %d)",
		tableprefix, repeater->id, repeater->slot[timeslot-1].src_id, timeslot, repeater->slot[timeslot-1].dst_id,
		repeater->slot[timeslot-1].call_type, (long long)repeater->slot[timeslot-1].call_started_at, (long long)repeater->slot[timeslot-1].call_ended_at,
		repeater->slot[timeslot-1].rssi, repeater->slot[timeslot-1].avg_rssi);
	free(tableprefix);

	remotedb_query(query);
}

void remotedb_update_repeater(repeater_t *repeater) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || repeater->id == 0 || strlen(repeater->callsign) == 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "replace into `%slive-repeaters` (`callsign`, `id`, `type`, `fwversion`, `dlfreq`, `ulfreq`, `lastactive`) "
		"values ('%s', %u, '%s', '%s', %u, %u, from_unixtime(%lld))",
		tableprefix, repeater->callsign, repeater->id, repeater->type, repeater->fwversion,
		repeater->dlfreq, repeater->ulfreq, (long long)repeater->last_active_time);
	free(tableprefix);

	remotedb_query(query);
}

void remotedb_update_repeater_lastactive(repeater_t *repeater) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || repeater->id == 0 || strlen(repeater->callsign) == 0)
		return;

	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "update `%slive-repeaters` set `lastactive` = from_unixtime(%lld) where `id` = %u",
		tableprefix, (long long)repeater->last_active_time, repeater->id);
	free(tableprefix);

	remotedb_query(query);
}

void remotedb_update(repeater_t *repeater) {
	remotedb_update_timeslot(repeater, 1);
	remotedb_update_timeslot(repeater, 2);
	remotedb_update_repeater_lastactive(repeater);
}

static void remotedb_connect(void) {
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

void remotedb_maintain(void) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	console_log(LOGLEVEL_REMOTEDB "remotedb: clearing entries older than %u seconds\n", config_get_remotedbdeleteolderthansec());
	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "delete from `%slive` where unix_timestamp(`startts`) < (UNIX_TIMESTAMP() - %u) or `startts` = NULL",
		tableprefix, config_get_remotedbdeleteolderthansec());
	free(tableprefix);

	remotedb_query(query);
}

void remotedb_maintain_repeaterlist(void) {
	char *tableprefix = NULL;
	char query[512] = {0,};

	console_log(LOGLEVEL_REMOTEDB "remotedb: clearing repeater entries older than %u seconds\n", config_get_repeaterinactivetimeoutinsec());
	tableprefix = config_get_remotedbtableprefix();
	snprintf(query, sizeof(query), "delete from `%slive-repeaters` where unix_timestamp(`lastactive`) < (UNIX_TIMESTAMP() - %u) or `lastactive` = NULL",
		tableprefix, config_get_repeaterinactivetimeoutinsec());
	free(tableprefix);

	remotedb_query(query);
}

void remotedb_process(void) {
	static time_t lastconnecttriedat = 0;
	static time_t lastmaintenanceat = 0;
	static time_t lastrepeaterlistmaintenanceat = 0;

	if (remotedb_conn != NULL) {
		if (time(NULL)-lastconnecttriedat > config_get_remotedbreconnecttrytimeoutinsec()) {
			if (mysql_ping(remotedb_conn) != 0)
				remotedb_connect();
			lastconnecttriedat = time(NULL);
		}

		if (time(NULL)-lastmaintenanceat > config_get_remotedbmaintenanceperiodinsec()) {
			remotedb_maintain();
			lastmaintenanceat = time(NULL);
		}

		if (time(NULL)-lastrepeaterlistmaintenanceat > config_get_repeaterinactivetimeoutinsec()) {
			remotedb_maintain_repeaterlist();
			lastrepeaterlistmaintenanceat = time(NULL);
		}
	}

}

void remotedb_init(void) {
	unsigned int opt;
	char *server = config_get_remotedbhost();

	console_log("remotedb: init\n");

	if (strlen(server) != 0) {
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

			remotedb_connect();
		}
	}
	free(server);
}

void remotedb_deinit(void) {
	console_log("remotedb: deinit\n");

	if (remotedb_conn != NULL) {
		mysql_close(remotedb_conn);
		remotedb_conn = NULL;
	}
}
