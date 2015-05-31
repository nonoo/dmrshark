#include <config/defaults.h>

#include "command.h"
#include "log.h"
#include "types.h"
#include "base.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>
#include <libs/comm/snmp.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>

void command_process(char *input_buffer) {
	extern base_flags_t base_flags;
	loglevel_t loglevel;

	char *tok = strtok(input_buffer, " ");

	if (tok == NULL)
		return;

	if (strcmp(tok, "help") == 0 || strcmp(tok, "h") == 0) {
		console_log("  ver                             - version\n");
		console_log("  log (loglevel)                  - get/set loglevel\n");
		console_log("  exit                            - exits the application\n");
		console_log("  rssi [host]                     - reads rssi value from host using snmp\n");
		return;
	}

	if (strcmp(tok, "ver") == 0) {
		log_ver();
		return;
	}

	if (strcmp(tok, "log") == 0) {
		loglevel = console_get_loglevel();
		tok = strtok(NULL, " ");
		if (tok != NULL) {
			if (strcmp(tok, "off") == 0 || tok[0] == '0') {
				if (loglevel.raw == 0)
					memset((void *)&loglevel.raw, 0xff, sizeof(loglevel.raw));
				else
					loglevel.raw = 0;
			} else if (strcmp(tok, "debug") == 0)
				loglevel.flags.debug = !loglevel.flags.debug;
			else if (strcmp(tok, "comm-ip") == 0)
				loglevel.flags.comm_ip = !loglevel.flags.comm_ip;
			else if (strcmp(tok, "comm-dmr") == 0)
				loglevel.flags.comm_dmr = !loglevel.flags.comm_dmr;

			config_set_loglevel(&loglevel);
			console_set_loglevel(&loglevel);
		}
		log_loglevel(&loglevel);
		return;
	}

	if (strcmp(tok, "exit") == 0) {
		base_flags.sigexit = 1;
		return;
	}

	if (strcmp(tok, "rssi") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		console_log("starting rssi read request to %s...\n", tok);
		snmp_start_read_rssi(tok);
		return;
	}

	if (strcmp(tok, "info") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		console_log("starting info read request to %s...\n", tok);
		snmp_start_read_repeaterinfo(tok);
		return;
	}

	// TODO: remove
	if (strcmp(tok, "rsi") == 0) {
		tok = "192.168.3.107";
		console_log("starting rssi read request to %s...\n", tok);
		snmp_start_read_rssi(tok);
		return;
	}
	if (strcmp(tok, "inf") == 0) {
		tok = "192.168.3.107";
		console_log("starting info read request to %s...\n", tok);
		snmp_start_read_repeaterinfo(tok);
		return;
	}

	console_log("error: unknown command, see help, or go get a beer.\n");
}
