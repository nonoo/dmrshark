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

#include <libs/base/base.h>
#include <libs/base/log.h>
#include <libs/daemon/console.h>
#include <libs/daemon/daemon.h>
#include <libs/config/config.h>
#include <libs/config/config-voicestreams.h>
#include <libs/comm/comm.h>
#include <libs/remotedb/remotedb.h>
#include <libs/coding/coding.h>
#include <libs/voicestreams/voicestreams.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

static char *dmrshark_configfilename = CONFIGFILENAME;
static flag_t dmrshark_daemonize = 1;
static flag_t dmrshark_consoleclient = 0;
static char *dmrshark_directory = NULL;

static void dmrshark_printversion(void) {
	console_log(APPNAME " by ha2non v%u.%u.%u ", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
	console_log(__TIME__ " " __DATE__ " " GITHASH "\n");
}

static void dmrshark_processcommandline(int argc, char **argv) {
	int c;

	while ((c = getopt(argc, argv, "hvfd:s:rc:i")) != -1) {
		switch (c) {
			case '?': // Unknown option
			case 'h':
				dmrshark_printversion();
				console_log("usage:\n");
				console_log("       -h         - this help\n");
				console_log("       -v         - version\n");
				console_log("       -f         - run in foreground\n");
				console_log("       -c [file]  - use given config file\n");
				console_log("       -r         - connect console to background process (implies -f)\n");
				console_log("       -d [dir]   - change current directory on startup\n");
				exit(0);
			case 'v':
				dmrshark_printversion();
				exit(0);
			case 'f':
				dmrshark_daemonize = 0;
				break;
			case 'c':
				dmrshark_configfilename = optarg;
				break;
			case 'r':
				dmrshark_daemonize = 0;
				dmrshark_consoleclient = 1;
				break;
			case 'd':
				dmrshark_directory = optarg;
				break;
			default:
				exit(1);
		}
	}
}

int main(int argc, char *argv[]) {
	dmrshark_processcommandline(argc, argv);

	// Changing the current working directory
	if (!daemon_changecwd(dmrshark_directory))
		return 1;

	config_init(dmrshark_configfilename);
	switch (daemon_init(dmrshark_daemonize, dmrshark_consoleclient)) {
		case DAEMON_INIT_RESULT_FORKED_PARENTEXIT:
			return 0;
		case DAEMON_INIT_RESULT_FORK_ERROR:
		case DAEMON_INIT_RESULT_CONSOLECLIENT_ERROR:
			return 1;
		default:
			break;
	}
	if (!daemon_is_consoleclient()) {
		config_voicestreams_init();
		base_init();
		remotedb_init();
		coding_init();
		voicestreams_init();
		if (!comm_init()) {
			daemon_deinit();
			return 1;
		}
	}

	console_log("\n");
	dmrshark_printversion();
	console_log("*** ready.\n");

	while (daemon_process()) {
		if (!daemon_is_consoleclient()) {
			base_process();
			comm_process();
		}
	}

	if (!daemon_is_consoleclient()) {
		comm_deinit();
		voicestreams_deinit();
		remotedb_deinit();
		base_deinit();
	}
	daemon_deinit();
	config_deinit();

	pthread_exit(NULL);

	return 0;
}
