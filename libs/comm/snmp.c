#include <config/defaults.h>

#include "snmp.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>

#include <errno.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define OID_RSSI_TS1 "1.3.6.1.4.1.40297.1.2.1.2.9.0"
#define OID_RSSI_TS2 "1.3.6.1.4.1.40297.1.2.1.2.10.0"

static oid oid_rssi_ts1[MAX_OID_LEN];
static size_t oid_rssi_ts1_length = 0;
static oid oid_rssi_ts2[MAX_OID_LEN];
static size_t oid_rssi_ts2_length = 0;
static int last_rssi_ts1 = 0;
static int last_rssi_ts2 = 0;
struct snmp_session *active_session = NULL;

static int snmp_get_rssi_cb(int operation, struct snmp_session *sp, int reqid, struct snmp_pdu *pdu, void *magic) {
	//struct session *host = (struct session *)magic;
	char value[15] = {0,};
	char *endptr = NULL;
	int value_num = 0;
	struct variable_list *vars = NULL;

	if (sp != active_session)
		return 1;

	if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
		if (pdu->errstat == SNMP_ERR_NOERROR) {
			for (vars = pdu->variables; vars; vars = vars->next_variable) {
				if (memcmp(vars->name, oid_rssi_ts1, min(vars->name_length, oid_rssi_ts1_length)) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp: invalid ts1 rssi value received: %s\n", value);
					else {
						last_rssi_ts1 = value_num;
						console_log("snmp: got ts1 rssi value %d\n", last_rssi_ts1);
						// TODO: store timestamp
					}
				} else if (memcmp(vars->name, oid_rssi_ts2, min(vars->name_length, oid_rssi_ts2_length)) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp: invalid ts2 rssi value received: %s\n", value);
					else {
						last_rssi_ts2 = value_num;
						console_log("snmp: got ts2 rssi value %d\n", last_rssi_ts2);
						// TODO: store timestamp
					}
				}
			}
		} else
			console_log(LOGLEVEL_DEBUG "snmp: rssi read error\n");
    } else
    	console_log(LOGLEVEL_DEBUG "snmp: rssi read timeout\n");

	active_session = NULL;

	return 0;
}

void snmp_start_read_rssi(char *host) {
	struct snmp_pdu *pdu;
	struct snmp_session session;
	const char *community = "public";

	if (oid_rssi_ts1_length == 0 || oid_rssi_ts2_length == 0)
		return;

	if (active_session)
		snmp_close(active_session);

	snmp_sess_init(&session);
	session.version = SNMP_VERSION_1;
	session.peername = strdup(host);
	session.community = (unsigned char *)strdup(community);
	session.community_len = strlen(community);
	session.callback = snmp_get_rssi_cb;
	session.callback_magic = host;
	if (!(active_session = snmp_open(&session))) {
		console_log("snmp error: error opening session to host %s\n", host);
		return;
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, oid_rssi_ts1, oid_rssi_ts1_length);
	snmp_add_null_var(pdu, oid_rssi_ts2, oid_rssi_ts2_length);
	if (!snmp_send(active_session, pdu))
		console_log("snmp error: error sending request to host %s\n", host);
	free(session.peername);
	free(session.community);
}

void snmp_process(void) {
    int nfds = 0;
    int block = 1;
    fd_set fdset;
    struct timeval timeout;

	if (active_session == NULL)
		return;

	FD_ZERO(&fdset);
	snmp_select_info(&nfds, &fdset, &timeout, &block);
	// Timeout is handled by daemon-poll.
	daemon_poll_setmaxtimeout(timeout.tv_sec*1000+timeout.tv_usec/1000);
	// As timeout is handled by daemon-poll, we want select() to return immediately here.
	timeout.tv_sec = timeout.tv_usec = 0;
	nfds = select(nfds, &fdset, NULL, NULL, &timeout);
	if (nfds > 0)
		snmp_read(&fdset);
	else
		snmp_timeout();
}

void snmp_init(void) {
	init_snmp(APPNAME);

	oid_rssi_ts1_length = MAX_OID_LEN;
	if (!read_objid(OID_RSSI_TS1, oid_rssi_ts1, &oid_rssi_ts1_length))
		console_log("snmp error: can't parse ts1 rssi oid (%s)\n", OID_RSSI_TS1);
	oid_rssi_ts2_length = MAX_OID_LEN;
	if (!read_objid(OID_RSSI_TS2, oid_rssi_ts2, &oid_rssi_ts2_length))
		console_log("snmp error: can't parse ts2 rssi oid (%s)\n", OID_RSSI_TS2);
}
