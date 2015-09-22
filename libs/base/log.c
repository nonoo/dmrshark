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

#include "log.h"

void log_ver(void) {
	console_log("ver: v%u.%u.%u", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
	console_log(" " __TIME__ " " __DATE__ " " GITHASH "\n");
}

void log_loglevel(loglevel_t *loglevel) {
	console_log("loglevel:\n");

	console_log("  debug ");
	if (loglevel->flags.debug)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  ipsc ");
	if (loglevel->flags.ipsc)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  comm-ip ");
	if (loglevel->flags.comm_ip)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  dmr ");
	if (loglevel->flags.dmr)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  dmrlc ");
	if (loglevel->flags.dmrlc)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  dmrdata ");
	if (loglevel->flags.dmrdata)
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

	console_log("  heartbeat ");
	if (loglevel->flags.heartbeat)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  remotedb ");
	if (loglevel->flags.remotedb)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  voicestreams ");
	if (loglevel->flags.voicestreams)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  coding ");
	if (loglevel->flags.coding)
		console_log("on\n");
	else
		console_log("off\n");

	console_log("  httpserver ");
	if (loglevel->flags.httpserver)
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
