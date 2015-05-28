#include <config/defaults.h>

#include "command.h"
#include "log.h"
#include "types.h"
#include "base.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>

void command_process(char *input_buffer) {
	extern loglevel_t loglevel;
	extern base_flags_t base_flags;

	char *tok = strtok(input_buffer, " ");

	if (tok == NULL)
		return;

	if (strcmp(tok, "help") == 0 || strcmp(tok, "h") == 0) {
		console_log("  ver                             - version\n");
		console_log("  log (loglevel)                  - get/set loglevel\n");
		console_log("  exit                            - exits the application\n");
		return;
	}

	if (strcmp(tok, "ver") == 0) {
		log_ver();
		return;
	}

	if (strcmp(tok, "log") == 0) {
		tok = strtok(NULL, " ");
		if (tok != NULL) {
			if (strcmp(tok, "off") == 0 || tok[0] == '0') {
				if (loglevel.raw == 0)
					memset((void *)&loglevel.raw, 0xff, sizeof(loglevel.raw));
				else
					loglevel.raw = 0;;
			} else if (strcmp(tok, "debug") == 0)
				loglevel.flags.debug = !loglevel.flags.debug;

			config_set_loglevel(&loglevel);
		}
		log_loglevel(&loglevel);
		return;
	}

	if (strcmp(tok, "exit") == 0) {
		base_flags.sigexit = 1;
		return;
	}

	console_log("error: unknown command, see help, or go get a beer.\n");
}
