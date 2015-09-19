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

#include "snmp.h"
#include "repeaters.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/remotedb/remotedb.h>

#include <errno.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <iconv.h>
#include <ctype.h>

#define OID_RSSI_TS1		"1.3.6.1.4.1.40297.1.2.1.2.9.0"
#define OID_RSSI_TS2		"1.3.6.1.4.1.40297.1.2.1.2.10.0"
#define OID_ID				"1.3.6.1.4.1.40297.1.2.4.7.0"
#define OID_REPEATERTYPE	"1.3.6.1.4.1.40297.1.2.4.1.0"
#define OID_FWVERSION		"1.3.6.1.4.1.40297.1.2.4.3.0"
#define OID_CALLSIGN		"1.3.6.1.4.1.40297.1.2.4.6.0"
#define OID_DLFREQ			"1.3.6.1.4.1.40297.1.2.4.10.0"
#define OID_ULFREQ			"1.3.6.1.4.1.40297.1.2.4.11.0"
#define OID_PSUVOLTAGE		"1.3.6.1.4.1.40297.1.2.1.2.1.0"
#define OID_PATEMPERATURE	"1.3.6.1.4.1.40297.1.2.1.2.2.0"
#define OID_VSWR			"1.3.6.1.4.1.40297.1.2.1.2.4.0"
#define OID_TXFWDPOWER		"1.3.6.1.4.1.40297.1.2.1.2.5.0"
#define OID_TXREFPOWER		"1.3.6.1.4.1.40297.1.2.1.2.6.0"

typedef union {
	int v_int;
	float v_float;
	uint8_t v_bytes[4];
} snmp_val_result_t;

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
static oid oid_psuvoltage[MAX_OID_LEN];
static size_t oid_psuvoltage_length = 0;
static oid oid_patemperature[MAX_OID_LEN];
static size_t oid_patemperature_length = 0;
static oid oid_vswr[MAX_OID_LEN];
static size_t oid_vswr_length = 0;
static oid oid_txfwdpower[MAX_OID_LEN];
static size_t oid_txfwdpower_length = 0;
static oid oid_txrefpower[MAX_OID_LEN];
static size_t oid_txrefpower_length = 0;

static struct snmp_session *snmp_session_repeaterinfo = NULL;
static flag_t snmp_repeaterinfo_received = 0;

static struct snmp_session *snmp_session_repeaterstatus = NULL;
static flag_t snmp_repeaterstatus_received = 0;

static snmp_val_result_t snmp_get_result_value(char *snmp_str) {
	snmp_val_result_t result = { .v_int = 0, .v_float = 0 };
	char *endptr = NULL;

	if (strstr(snmp_str, "INTEGER: ") == snmp_str) {
		errno = 0;
		result.v_int = strtol(snmp_str+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
		if (*endptr != 0 || errno != 0)
			console_log(LOGLEVEL_SNMP LOGLEVEL_DEBUG "snmp: invalid value received: %s\n", snmp_str);
		return result;
	}

	if (strstr(snmp_str, "Hex-STRING: ") == snmp_str) {
		snmp_str[0] = '0';
		snmp_str[1] = 'x';
		snmp_str[2] = snmp_str[21];
		snmp_str[3] = snmp_str[22];
		snmp_str[4] = snmp_str[18];
		snmp_str[5] = snmp_str[19];
		snmp_str[6] = snmp_str[15];
		snmp_str[7] = snmp_str[16];
		snmp_str[8] = snmp_str[12];
		snmp_str[9] = snmp_str[13];
		snmp_str[10] = 0;
		sscanf(snmp_str, "%x", &result.v_int);
		return result;
	}

	if (strstr(snmp_str, "STRING: ") == snmp_str) {
		result.v_bytes[0] = snmp_str[9];
		result.v_bytes[1] = snmp_str[10];
		result.v_bytes[2] = snmp_str[11];
		result.v_bytes[3] = snmp_str[12];
		return result;
	}
	console_log(LOGLEVEL_SNMP LOGLEVEL_DEBUG "snmp: got unknown value string: %s\n", snmp_str);
	return result;
}

static int snmp_get_repeaterstatus_cb(int operation, struct snmp_session *sp, int reqid, struct snmp_pdu *pdu, void *magic) {
	char value[30] = {0,};
	struct variable_list *vars = NULL;
	repeater_t *repeater = NULL;
	in_addr_t ipaddr;
	flag_t dodbupdate = 0;
	snmp_val_result_t val_result;

	if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
		if (pdu->errstat == SNMP_ERR_NOERROR) {
			ipaddr = inet_addr(sp->peername);
			repeater = repeaters_findbyip((struct in_addr *)&ipaddr);

			for (vars = pdu->variables; vars; vars = vars->next_variable) {
				if (netsnmp_oid_equals(vars->name, vars->name_length, oid_rssi_ts1, oid_rssi_ts1_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_int > -200) {
						if (repeater != NULL) {
							repeater->slot[0].rssi = val_result.v_int;
							if (repeater->slot[0].avg_rssi == 0)
								repeater->slot[0].avg_rssi = val_result.v_int;
							else
								repeater->slot[0].avg_rssi = (repeater->slot[0].avg_rssi+val_result.v_int)/2.0;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got ts1 rssi value %d\n", sp->peername, val_result.v_int);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_rssi_ts2, oid_rssi_ts2_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_int > -200) {
						if (repeater != NULL) {
							repeater->slot[1].rssi = val_result.v_int;
							if (repeater->slot[1].avg_rssi == 0)
								repeater->slot[1].avg_rssi = val_result.v_int;
							else
								repeater->slot[1].avg_rssi = (repeater->slot[1].avg_rssi+val_result.v_int)/2.0;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got ts2 rssi value %d\n", sp->peername, val_result.v_int);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_psuvoltage, oid_psuvoltage_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_float >= 0) {
						if (repeater != NULL) {
							repeater->psuvoltage = val_result.v_float;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got psu voltage value %f\n", sp->peername, val_result.v_float);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_patemperature, oid_patemperature_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_float >= 0) {
						if (repeater != NULL) {
							repeater->patemperature = val_result.v_float;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got pa temperature value %f\n", sp->peername, val_result.v_float);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_vswr, oid_vswr_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_float >= 0) {
						if (repeater != NULL) {
							repeater->vswr = val_result.v_float;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got vswr value %f\n", sp->peername, val_result.v_float);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_txfwdpower, oid_txfwdpower_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_float >= 0) {
						if (repeater != NULL) {
							repeater->txfwdpower = val_result.v_float;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got tx fwd power value %f\n", sp->peername, val_result.v_float);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_txrefpower, oid_txrefpower_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					val_result = snmp_get_result_value(value);
					if (val_result.v_float >= 0) {
						if (repeater != NULL) {
							repeater->txrefpower = val_result.v_float;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got tx ref power value %f\n", sp->peername, val_result.v_float);
					}
				}
			}

			if (dodbupdate) {
				remotedb_update(repeater);
				remotedb_update_repeater(repeater);
			}

			snmp_repeaterstatus_received = 1;
		} else
			console_log(LOGLEVEL_SNMP "snmp: repeater status read error\n");
    } else
    	console_log(LOGLEVEL_SNMP "snmp: repeater status read timeout\n");

	return 1;
}

void snmp_start_read_repeaterstatus(char *host) {
	struct snmp_pdu *pdu;
	struct snmp_session session;
	const char *community = "public";

	if (oid_rssi_ts1_length == 0 || oid_rssi_ts2_length == 0 || oid_psuvoltage_length == 0 ||
		oid_patemperature_length == 0 || oid_vswr_length == 0 || oid_txfwdpower_length == 0 ||
		oid_txrefpower_length == 0)
			return;

	snmp_repeaterstatus_received = 0;

	if (snmp_session_repeaterstatus != NULL) {
		snmp_close(snmp_session_repeaterstatus);
		snmp_session_repeaterstatus = NULL;
	}

	snmp_sess_init(&session);
	session.version = SNMP_VERSION_1;
	session.peername = strdup(host);
	session.community = (unsigned char *)strdup(community);
	session.community_len = strlen(community);
	session.callback = snmp_get_repeaterstatus_cb;
	if (!(snmp_session_repeaterstatus = snmp_open(&session))) {
		console_log(LOGLEVEL_SNMP "snmp error: error opening repeater status session to host %s\n", host);
		return;
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, oid_rssi_ts1, oid_rssi_ts1_length);
	snmp_add_null_var(pdu, oid_rssi_ts2, oid_rssi_ts2_length);
	snmp_add_null_var(pdu, oid_psuvoltage, oid_psuvoltage_length);
	snmp_add_null_var(pdu, oid_patemperature, oid_patemperature_length);
	snmp_add_null_var(pdu, oid_vswr, oid_vswr_length);
	snmp_add_null_var(pdu, oid_txfwdpower, oid_txfwdpower_length);
	snmp_add_null_var(pdu, oid_txrefpower, oid_txrefpower_length);
	if (!snmp_send(snmp_session_repeaterstatus, pdu))
		console_log(LOGLEVEL_SNMP "snmp error: error sending repeater status request to host %s\n", host);
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
	flag_t dodbupdate = 0;
	uint8_t i;

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
						console_log(LOGLEVEL_SNMP LOGLEVEL_DEBUG "snmp [%s]: invalid id value received: %s\n", sp->peername, value);
					else {
						if (repeater != NULL) {
							repeater->id = value_num;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got id value %d\n", sp->peername, value_num);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_repeatertype, oid_repeatertype_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					length = snmp_hexstring_to_bytearray(value+12, value_utf16, sizeof(value_utf16)); // +12: cutting "Hex-STRING: " text returned by snprint_value().
					snmp_utf16_to_utf8(value_utf16, length, value_utf8, sizeof(value_utf8));
					if (repeater != NULL) {
						strncpy(repeater->type, value_utf8, sizeof(repeater->type));
						dodbupdate = 1;
					}
					console_log(LOGLEVEL_SNMP "snmp [%s]: got repeater type value %s\n", sp->peername, value_utf8);
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_fwversion, oid_fwversion_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					length = snmp_hexstring_to_bytearray(value+12, value_utf16, sizeof(value_utf16)); // +12: cutting "Hex-STRING: " text returned by snprint_value().
					snmp_utf16_to_utf8(value_utf16, length, value_utf8, sizeof(value_utf8));
					if (repeater != NULL) {
						strncpy(repeater->fwversion, value_utf8, sizeof(repeater->fwversion));
						dodbupdate = 1;
					}
					console_log(LOGLEVEL_SNMP "snmp [%s]: got repeater fw version value %s\n", sp->peername, value_utf8);
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_callsign, oid_callsign_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					length = snmp_hexstring_to_bytearray(value+12, value_utf16, sizeof(value_utf16)); // +12: cutting "Hex-STRING: " text returned by snprint_value().
					snmp_utf16_to_utf8(value_utf16, length, value_utf8, sizeof(value_utf8));
					if (repeater != NULL) {
						for (i = 0; (value_utf8[i] && i < sizeof(repeater->callsign)); i++) {
							repeater->callsign[i] = value_utf8[i];
							repeater->callsign_lowercase[i] = tolower(value_utf8[i]);
						}
						repeater->callsign[i] = 0;
						repeater->callsign_lowercase[i] = 0;
						dodbupdate = 1;
					}
					console_log(LOGLEVEL_SNMP "snmp [%s]: got repeater callsign value %s\n", sp->peername, value_utf8);
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_dlfreq, oid_dlfreq_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_SNMP LOGLEVEL_DEBUG "snmp [%s]: invalid dl freq value received: %s\n", sp->peername, value);
					else {
						if (repeater != NULL) {
							repeater->dlfreq = value_num;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got dl freq value %d\n", sp->peername, value_num);
					}
				} else if (netsnmp_oid_equals(vars->name, vars->name_length, oid_ulfreq, oid_ulfreq_length) == 0) {
					snprint_value(value, sizeof(value), vars->name, vars->name_length, vars);
					errno = 0;
					value_num = strtol(value+9, &endptr, 10); // +9: cutting "INTEGER: " text returned by snprint_value().
					if (*endptr != 0 || errno != 0)
						console_log(LOGLEVEL_SNMP LOGLEVEL_DEBUG "snmp [%s]: invalid dl freq value received: %s\n", sp->peername, value);
					else {
						if (repeater != NULL) {
							repeater->ulfreq = value_num;
							dodbupdate = 1;
						}
						console_log(LOGLEVEL_SNMP "snmp [%s]: got ul freq value %d\n", sp->peername, value_num);
					}
				}
			}

			if (dodbupdate)
				remotedb_update_repeater(repeater);

			snmp_repeaterinfo_received = 1;
		} else
			console_log(LOGLEVEL_SNMP "snmp [%s]: repeater info read error\n", sp->peername);
    } else
    	console_log(LOGLEVEL_SNMP "snmp [%s]: repeater info read timeout\n", sp->peername);

	return 1;
}

void snmp_start_read_repeaterinfo(char *host) {
	struct snmp_pdu *pdu;
	struct snmp_session session;
	const char *community = "public";

	if (oid_id_length == 0)
		return;

	snmp_repeaterinfo_received = 0;

	if (snmp_session_repeaterinfo != NULL) {
		snmp_close(snmp_session_repeaterinfo);
		snmp_session_repeaterinfo = NULL;
	}

	snmp_sess_init(&session);
	session.version = SNMP_VERSION_1;
	session.peername = strdup(host);
	session.community = (unsigned char *)strdup(community);
	session.community_len = strlen(community);
	session.callback = snmp_get_repeaterinfo_cb;
	if (!(snmp_session_repeaterinfo = snmp_open(&session))) {
		console_log(LOGLEVEL_SNMP "snmp [%s]: error opening session\n", host);
		return;
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, oid_id, oid_id_length);
	snmp_add_null_var(pdu, oid_repeatertype, oid_repeatertype_length);
	snmp_add_null_var(pdu, oid_fwversion, oid_fwversion_length);
	snmp_add_null_var(pdu, oid_callsign, oid_callsign_length);
	snmp_add_null_var(pdu, oid_dlfreq, oid_dlfreq_length);
	snmp_add_null_var(pdu, oid_ulfreq, oid_ulfreq_length);
	if (!snmp_send(snmp_session_repeaterinfo, pdu))
		console_log(LOGLEVEL_SNMP "snmp [%s]: error sending repeater info request\n", host);
	free(session.peername);
	free(session.community);
}

void snmp_process(void) {
    int nfds = 0;
    int block = 1;
    fd_set fdset;
    struct timeval timeout = {0,};

	if (snmp_repeaterinfo_received) {
		snmp_repeaterinfo_received = 0;
		if (snmp_session_repeaterinfo != NULL) {
			snmp_close(snmp_session_repeaterinfo);
			snmp_session_repeaterinfo = NULL;
		}
	}

	if (snmp_repeaterstatus_received) {
		snmp_repeaterstatus_received = 0;
		if (snmp_session_repeaterstatus != NULL) {
			snmp_close(snmp_session_repeaterstatus);
			snmp_session_repeaterstatus = NULL;
		}
	}

	FD_ZERO(&fdset);
	if (snmp_select_info(&nfds, &fdset, &timeout, &block) <= 0)
		return;
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
	oid_psuvoltage_length = MAX_OID_LEN;
	if (!read_objid(OID_PSUVOLTAGE, oid_psuvoltage, &oid_psuvoltage_length))
		console_log("snmp error: can't parse psu voltage oid (%s)\n", OID_PSUVOLTAGE);
	oid_patemperature_length = MAX_OID_LEN;
	if (!read_objid(OID_PATEMPERATURE, oid_patemperature, &oid_patemperature_length))
		console_log("snmp error: can't parse pa temperature oid (%s)\n", OID_PATEMPERATURE);
	oid_vswr_length = MAX_OID_LEN;
	if (!read_objid(OID_VSWR, oid_vswr, &oid_vswr_length))
		console_log("snmp error: can't parse vswr oid (%s)\n", OID_VSWR);
	oid_txfwdpower_length = MAX_OID_LEN;
	if (!read_objid(OID_TXFWDPOWER, oid_txfwdpower, &oid_txfwdpower_length))
		console_log("snmp error: can't parse tx fwd power oid (%s)\n", OID_TXFWDPOWER);
	oid_txrefpower_length = MAX_OID_LEN;
	if (!read_objid(OID_TXREFPOWER, oid_txrefpower, &oid_txrefpower_length))
		console_log("snmp error: can't parse tx ref power oid (%s)\n", OID_TXREFPOWER);

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

	if (snmp_session_repeaterinfo != NULL) {
		snmp_close(snmp_session_repeaterinfo);
		snmp_session_repeaterinfo = NULL;
	}

	if (snmp_session_repeaterstatus != NULL) {
		snmp_close(snmp_session_repeaterstatus);
		snmp_session_repeaterstatus = NULL;
	}
}
