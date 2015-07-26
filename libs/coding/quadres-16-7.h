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

#ifndef QUADRES_16_7_H_
#define QUADRES_16_7_H_

#include <libs/base/types.h>

typedef struct {
	flag_t data[7];
	flag_t parity[9];
} quadres_16_7_codeword_t;

flag_t quadres_16_7_check(quadres_16_7_codeword_t *codeword);

void quadres_16_7_init(void);

#endif
