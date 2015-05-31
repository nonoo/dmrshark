#include <config/defaults.h>

#include "remotedb.h"

#include <libs/config/config.h>
#include <libs/comm/comm.h>

#include <stdlib.h>
#include <mysql/mysql.h>
#include <string.h>
#include <stdio.h>

static MYSQL *remotedb_conn = NULL;
static char *remotedb_tablename = NULL;

void remotedb_call_start_cb(repeater_t *repeater, uint8_t timeslot) {
	char query[255] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || remotedb_tablename == NULL)
		return;

	if (!repeater->slot[timeslot-1].call_running)
		return;

	snprintf(query, sizeof(query), "replace into `%s` (`repeaterid`, `srcid`, `timeslot`, `dstid`, `calltype`, `startts`) values (%u, %u, %u, %u, %u, from_unixtime(%lld))",
		remotedb_tablename, repeater->id, repeater->slot[timeslot-1].src_id, timeslot, repeater->slot[timeslot-1].dst_id,
		repeater->slot[timeslot-1].call_type, (long long)repeater->slot[timeslot-1].call_started_at);

	console_log(LOGLEVEL_DEBUG "remotedb: call start, sending query: %s\n", query);

	if (mysql_query(remotedb_conn, query)) {
		console_log(LOGLEVEL_DEBUG "remotedb error: %s\n", mysql_error(remotedb_conn));
		return;
	}
}

void remotedb_call_end_cb(repeater_t *repeater, uint8_t timeslot) {
	char query[255] = {0,};

	if (repeater == NULL || remotedb_conn == NULL || remotedb_tablename == NULL)
		return;

	if (repeater->slot[timeslot-1].call_running)
		return;

	snprintf(query, sizeof(query), "replace into `%s` (`repeaterid`, `srcid`, `timeslot`, `dstid`, `calltype`, `startts`, `endts`) values (%u, %u, %u, %u, %u, from_unixtime(%lld), from_unixtime(%lld))",
		remotedb_tablename, repeater->id, repeater->slot[timeslot-1].src_id, timeslot, repeater->slot[timeslot-1].dst_id,
		repeater->slot[timeslot-1].call_type, (long long)repeater->slot[timeslot-1].call_started_at, (long long)repeater->slot[timeslot-1].call_ended_at);

	console_log(LOGLEVEL_DEBUG "remotedb: call end, sending query: %s\n", query);

	if (mysql_query(remotedb_conn, query)) {
		console_log(LOGLEVEL_DEBUG "remotedb error: %s\n", mysql_error(remotedb_conn));
		return;
	}
}

void remotedb_init(void) {
	char *server = config_get_remotedbhost();
	char *user = config_get_remotedbuser();
	char *pass = config_get_remotedbpass();
	char *dbname = config_get_remotedbname();
	remotedb_tablename = config_get_remotedbtablename();
	my_bool opt;

	console_log("remotedb: init\n");

	if (strlen(server) != 0) {
		remotedb_conn = mysql_init(NULL);
		opt = 1;
		mysql_options(remotedb_conn, MYSQL_OPT_RECONNECT, &opt);
		console_log("remotedb: trying to connect to mysql server %s...\n", server);
		if (!mysql_real_connect(remotedb_conn, server, user, pass, dbname, 0, NULL, 0)) {
			console_log("remotedb error: can't connect to remote db: %s\n", mysql_error(remotedb_conn));
			mysql_close(remotedb_conn);
			remotedb_conn = NULL;
		} else
			console_log("remotedb: connected\n");
	}
	free(server);
	free(user);
	free(pass);
	free(dbname);
}

void remotedb_deinit(void) {
	console_log("remotedb: deinit\n");

	if (remotedb_conn != NULL) {
		mysql_close(remotedb_conn);
		remotedb_conn = NULL;
	}
	free(remotedb_tablename);
	remotedb_tablename = NULL;
}
