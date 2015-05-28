#include <config/defaults.h>

#include <libs/base/base.h>
#include <libs/base/log.h>
#include <libs/daemon/console.h>
#include <libs/daemon/daemon.h>
#include <libs/config/config.h>
#include <libs/comm/comm.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

static char *node_configfilename = CONFIGFILENAME;
static flag_t node_daemonize = 1;
static flag_t node_consoleclient = 0;
static char *node_directory = NULL;

static void node_printversion(void) {
	console_log("node v%u.%u.%u-a%u ", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, APPID);
	console_log(__TIME__ " " __DATE__ " " GITHASH "\n");
}

static void node_processcommandline(int argc, char **argv) {
	int c;

	while ((c = getopt(argc, argv, "hvfd:s:rc:i")) != -1) {
		switch (c) {
			case '?': // Unknown option
			case 'h':
				node_printversion();
				console_log("usage:\n");
				console_log("       -h         - this help\n");
				console_log("       -v         - version\n");
				console_log("       -f         - run in foreground\n");
				console_log("       -c [file]  - use given config file\n");
				console_log("       -r         - connect console to background process (implies -f)\n");
				console_log("       -d [dir]   - change current directory on startup\n");
				exit(0);
			case 'v':
				node_printversion();
				exit(0);
			case 'f':
				node_daemonize = 0;
				break;
			case 'c':
				node_configfilename = optarg;
				break;
			case 'r':
				node_daemonize = 0;
				node_consoleclient = 1;
				break;
			case 'd':
				node_directory = optarg;
				break;
			default:
				exit(1);
		}
	}
}

int main(int argc, char *argv[]) {
	node_processcommandline(argc, argv);

	// Changing the current working directory
	if (!daemon_changecwd(node_directory))
		return 1;

	config_init(node_configfilename);
	switch (daemon_init(node_daemonize, node_consoleclient)) {
		case DAEMON_INIT_RESULT_FORKED_PARENTEXIT:
			return 0;
		case DAEMON_INIT_RESULT_FORK_ERROR:
		case DAEMON_INIT_RESULT_CONSOLECLIENT_ERROR:
			return 1;
		default:
			break;
	}
	if (!daemon_is_consoleclient()) {
		base_init();
		comm_init();
	}

	console_log("\n");
	node_printversion();
	console_log("*** ready.\n");

	while (daemon_process()) {
		if (!daemon_is_consoleclient()) {
			base_process();
			comm_process();
		}
	}

	if (!daemon_is_consoleclient()) {
		comm_deinit();
		base_deinit();
	}
	daemon_deinit();
	config_deinit();

	return 0;
}
