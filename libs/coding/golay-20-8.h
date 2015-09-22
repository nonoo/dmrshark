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

#ifndef GOLAY_20_8_H_
#define GOLAY_20_8_H_

#include <libs/base/types.h>

typedef struct {
	flag_t bits[12];
} golay_20_8_parity_bits_t;

golay_20_8_parity_bits_t *golay_20_8_get_parity_bits(flag_t bits[8]);

flag_t golay_20_8_check_and_repair(flag_t bits[20]);
void golay_20_8_init(void);

#endif
