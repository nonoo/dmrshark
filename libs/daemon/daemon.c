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

#include "daemon.h"
#include "daemon-poll.h"
#include "daemon-consoleserver.h"
#include "daemon-consoleclient.h"
#include "console.h"
#include "ttyconsole.h"

#include <libs/base/types.h>
#include <libs/config/config.h>

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

extern volatile base_flags_t base_flags;

static flag_t daemon_daemonize = 1;
// Storing these flags separately, as printing to the console can happen before daemon_init().
static flag_t daemon_consoleclient = 0;
static flag_t daemon_consoleserver = 0;

flag_t daemon_changecwd(char *directory) {
	if (directory != NULL) {
		console_log("daemon: changing directory to %s\n", directory);
		if (chdir(directory) < 0) {
			console_log("daemon error: can't change directory\n");
			return 0;
		}
	}
	return 1;
}

static void daemon_removepidfile(void) {
	char *pidfilename = config_get_pidfilename();
	unlink(pidfilename);
	free(pidfilename);
}

static void daemon_sighandler(int signal) {
	switch (signal) {
		case SIGHUP:
			console_log("daemon: SIGHUP received\n");
			config_deinit();
			config_init(NULL);
			break;
		case SIGINT:
			if (base_flags.sigexit) {
				console_log("daemon: SIGINT received again, exiting\n");
				daemon_removepidfile();
				exit(0);
			}
			console_log("daemon: SIGINT received\n");
			base_flags.sigexit = 1;
			break;
		case SIGTERM:
			if (base_flags.sigexit) {
				console_log("daemon: SIGTERM received again, exiting\n");
				daemon_removepidfile();
				exit(0);
			}
			console_log("daemon: SIGTERM received\n");
			base_flags.sigexit = 1;
			break;
	}
}

static void daemon_writepidfile(void) {
	char *pidfilename = config_get_pidfilename();
	FILE *f = fopen(pidfilename, "w");
	if (f) {
		fprintf(f, "%d\n", getpid());
		fclose(f);
	}
	free(pidfilename);
}

flag_t daemon_is_consoleclient(void) {
	return daemon_consoleclient;
}

flag_t daemon_is_consoleserver(void) {
	return daemon_consoleserver;
}

flag_t daemon_is_daemonize(void) {
	return daemon_daemonize;
}

// This function puts the executable name of pid to exename.
static int daemon_getexename(long pid, char *exename, int exenamesize) {
	FILE *fp = NULL;
	char state;

	snprintf(exename, exenamesize, "/proc/%ld/stat", pid);
	fp = fopen(exename, "r");
	if (!fp)
		return -1;
	if ((fscanf(fp, "%ld (%[^)]) %c", &pid, exename, &state)) != 3) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return 0;
}

static flag_t daemon_isalreadyrunning(void) {
    DIR* dir;
    struct dirent* ent;
	char currentpname[100] = {0,};
	char pname[100] = {0,};

    if (!(dir = opendir("/proc"))) {
		console_log("daemon error: can't detect if daemon is already running in the background.\n");
        return 0;
    }

	// Getting current executable name. Maybe we should use readlink() on /proc/pid/exe,
	// so multiple instances of NOT the same executable would be allowed.
	if (daemon_getexename(getpid(), currentpname, sizeof(currentpname)) < 0) {
		console_log("daemon error: can't detect if daemon is already running in the background.\n");
        return 0;
	}

	while ((ent = readdir(dir)) != NULL) {
		long lpid = atol(ent->d_name);
		if (lpid < 0 || lpid == getpid())
			continue;

		if (daemon_getexename(lpid, pname, sizeof(pname)) < 0)
			continue;

	    if (!strcmp(pname, currentpname)) {
			closedir(dir);
			return 1;
		}
	}

	closedir(dir);
	return 0;
}

flag_t daemon_process(void) {
	daemon_poll_process();

	if (daemon_is_consoleclient()) {
		if (!daemon_consoleclient_process())
			base_flags.sigexit = 1;
	} else if (daemon_is_consoleserver()) {
		daemon_consoleserver_process();
		ttyconsole_process();
	}

	console_process();

	if (base_flags.sigexit)
		return 0;

	return 1;
}

flag_t daemon_init(flag_t daemonize, flag_t consoleclient) {
	char *daemonctlfile = config_get_daemonctlfile();

	console_log("daemon: init\n");

	daemon_daemonize = daemonize;

	if (consoleclient) // Won't allow daemonizing when in console client mode.
		daemon_daemonize = 0;
	else {
		// Trying to find and connect to the background process
		if (daemon_isalreadyrunning()) {
			console_log("daemon error: already running\n");
			free(daemonctlfile);
			return DAEMON_INIT_RESULT_FORK_ERROR;
		}
	}

	daemon_poll_init();

	if (daemon_daemonize) {
		console_log("daemon: forking to the background\n");
		pid_t sid;
		pid_t childpid = fork();

		if (childpid > 0) { // Fork successful, closing the parent
			free(daemonctlfile);
			return DAEMON_INIT_RESULT_FORKED_PARENTEXIT;
		}
		if (childpid < 0) { // Fork error, child not created
			console_log("daemon error: can't fork to the background\n");
			free(daemonctlfile);
			return DAEMON_INIT_RESULT_FORK_ERROR;
		}

		// This section is only executed by the forked child

		// Setting default file permissions to o+rw
		umask(~(S_IRUSR | S_IWUSR));

		// Creating a new SID
		sid = setsid();
		if (sid < 0) {
			console_log("daemon error: can't create sid, fork error\n");
			free(daemonctlfile);
			return DAEMON_INIT_RESULT_FORK_ERROR;
		}

		// Closing standard outputs, inputs as they isn't needed.
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
	}

	daemon_consoleclient = consoleclient;
	daemon_consoleserver = !consoleclient;

	signal(SIGHUP, daemon_sighandler);
	signal(SIGINT, daemon_sighandler);
	signal(SIGTERM, daemon_sighandler);
	signal(SIGPIPE, SIG_IGN);

	daemon_writepidfile();

	if (daemon_is_consoleclient() && !daemon_consoleclient_init()) {
		// Error reporting
		if (access(daemonctlfile, F_OK) < 0) // Control file doesn't exist?
			console_log("daemon error: %s not found, console server not running?\n", daemonctlfile);
		else
			console_log("daemon error: can't connect to remote console, exiting\n");

		daemon_removepidfile();
		free(daemonctlfile);
		return DAEMON_INIT_RESULT_CONSOLECLIENT_ERROR;
	}

	if (daemon_is_consoleserver())
		daemon_consoleserver_init();

	free(daemonctlfile);

	console_init();
	if (daemon_is_consoleserver())
		ttyconsole_init();

	return DAEMON_INIT_RESULT_OK;
}

void daemon_deinit(void) {
	console_log("daemon: deinit\n");
	console_deinit();
	if (daemon_is_consoleserver())
		ttyconsole_deinit();

	daemon_poll_deinit();
	daemon_removepidfile();
	daemon_consoleclient_deinit();
	daemon_consoleserver_deinit();
}
