#include <config/defaults.h>

#include "log.h"

void log_ver(void) {
	console_log("ver: v%u.%u.%u-a%u", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, APPID);
	console_log(" " __TIME__ " " __DATE__ " " GITHASH "\n");
}

void log_loglevel(loglevel_t *loglevel) {
	console_log("loglevel:\n");

	console_log("  debug ");
	if (loglevel->flags.debug)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  comm ");
	if (loglevel->flags.comm)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  comm-ip ");
	if (loglevel->flags.comm_ip)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  comm-dmr ");
	if (loglevel->flags.comm_dmr)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  snmp ");
	if (loglevel->flags.snmp)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  repeaters ");
	if (loglevel->flags.repeaters)
		console_log("on\n");
	else
		console_log("off\n");
}

void log_cmdmissingparam(void) {
	console_log("missing parameter(s), see help.\n");
}

void log_cmdinvalidparam(void) {
	console_log("invalid parameter(s), see help.\n");
}

void log_daemon_initconsoleserverfailed(void) {
	console_log("daemon error: failed to initialize console server\n");
}
