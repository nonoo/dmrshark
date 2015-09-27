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

#include "base.h"
#include "smstxbuf.h"

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

uint8_t base_bitstobyte(flag_t bits[8]) {
	uint8_t byteval = 0;
	uint8_t i;

	for (i = 0; i < 8; i++) {
		if (bits[i] == 1)
			byteval |= (1 << (7-i));
	}
	return byteval;
}

void base_bitstobytes(flag_t *bits, uint16_t bits_length, uint8_t *bytes, uint16_t bytes_length) {
	uint16_t i;

	for (i = 0; i < min(bits_length/8, bytes_length); i++)
		bytes[i] = base_bitstobyte(&bits[i*8]);
}

void base_bytetobits(uint8_t byte, flag_t *bits) {
	bits[0] = (byte & 128 ? 1 : 0);
	bits[1] = (byte & 64 ? 1 : 0);
	bits[2] = (byte & 32 ? 1 : 0);
	bits[3] = (byte & 16 ? 1 : 0);
	bits[4] = (byte & 8 ? 1 : 0);
	bits[5] = (byte & 4 ? 1 : 0);
	bits[6] = (byte & 2 ? 1 : 0);
	bits[7] = (byte & 1 ? 1 : 0);
}

void base_bytestobits(uint8_t *bytes, uint16_t bytes_length, flag_t *bits, uint16_t bits_length) {
	uint16_t i;

	for (i = 0; i < min(bits_length/8, bytes_length); i++)
		base_bytetobits(bytes[i], &bits[i*8]);
}

void base_process(void) {
	smstxbuf_process();
}

void base_init(void) {
	console_log("base: init\n");

	base_getorigid(&base_id);
}

void base_deinit(void) {
	console_log("base: deinit\n");

	smstxbuf_deinit();
}
