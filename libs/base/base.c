#include <config/defaults.h>

#include "base.h"

#include <libs/daemon/console.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

volatile base_flags_t base_flags;
base_id_t base_id;

void base_getorigid(base_id_t *id) {
	memset((void *)id, 0, sizeof(base_id_t));
	gethostname((char *)id, sizeof(base_id_t));
}

// Converts hex char pairs to bytes, storing the result in the input buffer.
// Returns the length of the successfully converted byte array.
uint8_t base_hexdatatodata(char *hexdata) {
	uint8_t i, length;
	char hexnum[3];
	char *endptr;

	if (!hexdata)
		return 0;

	length = strlen(hexdata)/2;
	hexnum[2] = 0;
	for (i = 0; i < length; i++) {
		hexnum[0] = hexdata[i*2];
		hexnum[1] = hexdata[i*2+1];
		errno = 0;
		hexdata[i] = (uint8_t)strtol(hexnum, &endptr, 16);
		if (*endptr != 0 || errno != 0)
			break;
	}
	return i;
}

void base_process(void) {
}

void base_init(void) {
	console_log("base: init\n");

	base_getorigid(&base_id);
}

void base_deinit(void) {
	console_log("base: deinit\n");
}
