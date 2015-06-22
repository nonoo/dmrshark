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

#ifndef CRC_H_
#define CRC_H_

#include "types.h"

void crc_calc_crc16_ccitt(uint16_t *crc, uint8_t in);
void crc_calc_crc16_ccitt_finish(uint16_t *crc);

void crc_calc_crc9(uint16_t *crc, uint8_t in, uint8_t in_bitscount);
void crc_calc_crc9_finish(uint16_t *crc, uint8_t out_bitscount);

void crc_calc_crc32(uint32_t *crc, uint8_t in);
void crc_calc_crc32_finish(uint32_t *crc);

#endif
