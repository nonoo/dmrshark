#include <config/defaults.h>

#include "snmp.h"
#include "repeaters.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>

#include <errno.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <iconv.h>

#define OID_RSSI_TS1		"1.3.6.1.4.1.40297.1.2.1.2.9.0"
#define OID_RSSI_TS2		"1.3.6.1.4.1.40297.1.2.1.2.10.0"
#define OID_ID				"1.3.6.1.4.1.40297.1.2.4.7.0"
#define OID_REPEATERTYPE	"1.3.6.1.4.1.40297.1.2.4.1.0"
#define OID_FWVERSION		"1.3.6.1.4.1.40297.1.2.4.3.0"
#define OID_CALLSIGN		"1.3.6.1.4.1.40297.1.2.4.6.0"
#define OID_DLFREQ			"1.3.6.1.4.1.40297.1.2.4.10.0"
#define OID_ULFREQ			"1.3.6.1.4.1.40297.1.2.4.11.0"

static iconv_t conv_utf16_utf8;
static oid oid_rssi_ts1[MAX_OID_LEN];
static size_t oid_rssi_ts1_length = 0;
static oid oid_rssi_ts2[MAX_OID_LEN];
static size_t oid_rssi_ts2_length = 0;
static oid oid_id[MAX_OID_LEN];
static size_t oid_id_length = 0;
static oid oid_repeatertype[MAX_OID_LEN];
static size_t oid_repeatertype_length = 0;
static oid oid_fwversion[MAX_OID_LEN];
static size_t oid_fwversion_length = 0;
static oid oid_callsign[MAX_OID_LEN];
static size_t oid_callsign_length = 0;
static oid oid_dlfreq[MAX_OID_LEN];
static size_t oid_dlfreq_length = 0;
static oid oid_ulfreq[MAX_OID_LEN];
static size_t oid_ulfreq_length = 0;

static int snmp_get_rssi_cb(int operation, struct snmp_session *sp, int reqid, struct snmp_pdu *pdu, void *magic) {
	char value[15] = {0,};
	char *endptr = NULL;
	int value_num = 0;
	struct variable_list *vars = NULL;
	repeater_t *repeater = NULL;
	in_addr_t ipaddr;

	if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
		if (pdu->errstat == SNMP_ERR_NOERROR) {
			ipaddr = inet_addr(sp->peername);
			repeater = repeaters_findbyip((struct in_addr *)&ipaddr);

			for (vars = pdu->variables; vars; vars = vars->next_variable) {
				if (netsnmp_oid_equals(vars->name, vars->name_length, oid_rssi_ts1, oid_rssi_ts1_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp: invalid ts1 rssi value received: %s\n", sp->peername);
					else {
						if (repeater != NULL)
							repeater->rssi_ts1 = value_num;
						console_log("snmp [%s]: got ts1 rssi value %d\n", sp->peername, value_num);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_rssi_ts2, oid_rssi_ts2_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp: invalid ts2 rssi value received: %s\n", value);
					else {
						if (repeater != NULL)
							repeater->rssi_ts2 = value_num;
						console_log("snmp [%s]: got ts2 rssi value %d\n", sp->peername, value_num);
					}
				}
			}
		} else
			console_log(LOGLEVEL_DEBUG "snmp: rssi read error\n");
    } else
    	console_log(LOGLEVEL_DEBUG "snmp: rssi read timeout\n");

	return 1;
}

void snmp_start_read_rssi(char *host) {
	struct snmp_pdu *pdu;
	struct snmp_session session;
	const char *community = "public";
	struct snmp_session *new_session = NULL;

	if (oid_rssi_ts1_length == 0 || oid_rssi_ts2_length == 0)
		return;

	snmp_sess_init(&session);
	session.version = SNMP_VERSION_1;
	session.peername = strdup(host);
	session.community = (unsigned char *)strdup(community);
	session.community_len = strlen(community);
	session.callback = snmp_get_rssi_cb;
	if (!(new_session = snmp_open(&session))) {
		console_log("snmp error: error opening session to host %s\n", host);
		return;
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, oid_rssi_ts1, oid_rssi_ts1_length);
	snmp_add_null_var(pdu, oid_rssi_ts2, oid_rssi_ts2_length);
	if (!snmp_send(new_session, pdu))
		console_log("snmp error: error sending rssi request to host %s\n", host);
	free(session.peername);
	free(session.community);
}

static int snmp_hexstring_to_bytearray(char *inbuf, char *outbuf, int outbuflen) {
	char *tok = NULL;
	int byteswritten = 0;
	char *endptr = NULL;

	tok = strtok(inbuf, " ");
	if (tok) {
		do {
			*outbuf = strtol(tok, &endptr, 16);
			byteswritten++;
			outbuf++;
			outbuflen--;
			tok = strtok(NULL, " ");
		} while (tok != NULL && outbuflen > 0);
	}

	return byteswritten;
}

static void snmp_utf16_to_utf8(char *str_utf16, int str_utf16_length, char *str_utf8, int str_utf8_length) {
	char *iconv_in = NULL;
	char *iconv_out = NULL;
	size_t iconv_in_length = 0;
	size_t iconv_out_length = 0;

	iconv_in = str_utf16;
	iconv_in_length = str_utf16_length;
	iconv_out = str_utf8;
	iconv_out_length = str_utf8_length;
	iconv(conv_utf16_utf8, &iconv_in, &iconv_in_length, &iconv_out, &iconv_out_length);
}

static int snmp_get_repeaterinfo_cb(int operation, struct snmp_session *sp, int reqid, struct snmp_pdu *pdu, void *magic) {
	char value[200] = {0,};
	char *endptr = NULL;
	int value_num = 0;
	struct variable_list *vars = NULL;
	repeater_t *repeater = NULL;
	in_addr_t ipaddr;
	char value_utf16[sizeof(value)/2] = {0,};
	char value_utf8[sizeof(value_utf16)/2] = {0,};
	int length = 0;

	if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
		if (pdu->errstat == SNMP_ERR_NOERROR) {
			ipaddr = inet_addr(sp->peername);
			repeater = repeaters_findbyip((struct in_addr *)&ipaddr);

			for (vars = pdu->variables; vars; vars = vars->next_variable) {
				if (netsnmp_oid_equals(vars->name, vars->name_length, oid_id, oid_id_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp [%s]: invalid id value received: %s\n", sp->peername, value);
					else {
						if (repeater)
							repeater->id = value_num;
						console_log("snmp [%s]: got id value %d\n", sp->peername, value_num);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_repeatertype, oid_repeatertype_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					length = snmp_hexstring_to_bytearray(value+12, value_utf16, sizeof(value_utf16)); // +12: cutting "Hex-STRING: " text returned by snprint_value().
					snmp_utf16_to_utf8(value_utf16, length, value_utf8, sizeof(value_utf8));
					if (repeater)
						strncpy(repeater->type, value_utf8, sizeof(repeater->type));
					console_log("snmp [%s]: got repeater type value %s\n", sp->peername, value_utf8);
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_fwversion, oid_fwversion_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					length = snmp_hexstring_to_bytearray(value+12, value_utf16, sizeof(value_utf16)); // +12: cutting "Hex-STRING: " text returned by snprint_value().
					snmp_utf16_to_utf8(value_utf16, length, value_utf8, sizeof(value_utf8));
					if (repeater)
						strncpy(repeater->fwversion, value_utf8, sizeof(repeater->fwversion));
					console_log("snmp [%s]: got repeater fw version value %s\n", sp->peername, value_utf8);
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_callsign, oid_callsign_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					length = snmp_hexstring_to_bytearray(value+12, value_utf16, sizeof(value_utf16)); // +12: cutting "Hex-STRING: " text returned by snprint_value().
					snmp_utf16_to_utf8(value_utf16, length, value_utf8, sizeof(value_utf8));
					if (repeater)
						strncpy(repeater->callsign, value_utf8, sizeof(repeater->callsign));
					console_log("snmp [%s]: got repeater callsign value %s\n", sp->peername, value_utf8);
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_dlfreq, oid_dlfreq_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp [%s]: invalid dl freq value received: %s\n", sp->peername, value);
					else {
						if (repeater)
							repeater->dlfreq = value_num;
						console_log("snmp [%s]: got dl freq value %d\n", sp->peername, value_num);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_ulfreq, oid_ulfreq_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_DEBUG "snmp [%s]: invalid dl freq value received: %s\n", sp->peername, value);
					else {
						if (repeater)
							repeater->ulfreq = value_num;
						console_log("snmp [%s]: got ul freq value %d\n", sp->peername, value_num);
					}
				}
			}
		} else
			console_log(LOGLEVEL_DEBUG "snmp [%s]: repeater info read error\n", sp->peername);
    } else
    	console_log(LOGLEVEL_DEBUG "snmp [%s]: repeater info read timeout\n", sp->peername);

	return 1;
}

void snmp_start_read_repeaterinfo(char *host) {
	struct snmp_pdu *pdu;
	struct snmp_session session;
	const char *community = "public";
	struct snmp_session *new_session = NULL;

	if (oid_id_length == 0)
		return;

	snmp_sess_init(&session);
	session.version = SNMP_VERSION_1;
	session.peername = strdup(host);
	session.community = (unsigned char *)strdup(community);
	session.community_len = strlen(community);
	session.callback = snmp_get_repeaterinfo_cb;
	if (!(new_session = snmp_open(&session))) {
		console_log("snmp [%s]: error opening session\n", host);
		return;
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, oid_id, oid_id_length);
	snmp_add_null_var(pdu, oid_repeatertype, oid_repeatertype_length);
	snmp_add_null_var(pdu, oid_fwversion, oid_fwversion_length);
	snmp_add_null_var(pdu, oid_callsign, oid_callsign_length);
	snmp_add_null_var(pdu, oid_dlfreq, oid_dlfreq_length);
	snmp_add_null_var(pdu, oid_ulfreq, oid_ulfreq_length);
	if (!snmp_send(new_session, pdu))
		console_log("snmp [%s]: error sending repeater info request\n", host);
	free(session.peername);
	free(session.community);
}

void snmp_process(void) {
    int nfds = 0;
    int block = 1;
    fd_set fdset;
    struct timeval timeout;

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
	console_log("snmp: init\n");

	init_snmp(APPNAME);
	conv_utf16_utf8 = iconv_open("UTF-8","UTF-16LE");

	oid_rssi_ts1_length = MAX_OID_LEN;
	if (!read_objid(OID_RSSI_TS1, oid_rssi_ts1, &oid_rssi_ts1_length))
		console_log("snmp error: can't parse ts1 rssi oid (%s)\n", OID_RSSI_TS1);
	oid_rssi_ts2_length = MAX_OID_LEN;
	if (!read_objid(OID_RSSI_TS2, oid_rssi_ts2, &oid_rssi_ts2_length))
		console_log("snmp error: can't parse ts2 rssi oid (%s)\n", OID_RSSI_TS2);

	oid_id_length = MAX_OID_LEN;
	if (!read_objid(OID_ID, oid_id, &oid_id_length))
		console_log("snmp error: can't parse id oid (%s)\n", OID_ID);
	oid_repeatertype_length = MAX_OID_LEN;
	if (!read_objid(OID_REPEATERTYPE, oid_repeatertype, &oid_repeatertype_length))
		console_log("snmp error: can't parse repeatertype oid (%s)\n", OID_REPEATERTYPE);
	oid_fwversion_length = MAX_OID_LEN;
	if (!read_objid(OID_FWVERSION, oid_fwversion, &oid_fwversion_length))
		console_log("snmp error: can't parse fwversion oid (%s)\n", OID_FWVERSION);
	oid_callsign_length = MAX_OID_LEN;
	if (!read_objid(OID_CALLSIGN, oid_callsign, &oid_callsign_length))
		console_log("snmp error: can't parse callsign oid (%s)\n", OID_CALLSIGN);
	oid_dlfreq_length = MAX_OID_LEN;
	if (!read_objid(OID_DLFREQ, oid_dlfreq, &oid_dlfreq_length))
		console_log("snmp error: can't parse callsign oid (%s)\n", OID_DLFREQ);
	oid_ulfreq_length = MAX_OID_LEN;
	if (!read_objid(OID_ULFREQ, oid_ulfreq, &oid_ulfreq_length))
		console_log("snmp error: can't parse callsign oid (%s)\n", OID_ULFREQ);
}

void snmp_deinit(void) {
	console_log("snmp: deinit\n");

	iconv_close(conv_utf16_utf8);
}
