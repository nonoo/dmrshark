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

#include "crc.h"

// This algorithm uses the shift register logic to implement CRC calculation.
// In the example we use the generator polynomial G(x)=x^16+x^12+x^5+1
// We create 16 shift registers, as this is a 16-bit CRC.
// We put the bits in from the input 8-bit value to the first (rightmost) shift register,
// then we take the bit which falls out from the last (leftmost) shift register, and
// xor it with every bit which go into a shift register which has x on a power in the
// generator polynomial. To simplify this operation, we calculate a hex CRC poly value
// and xor all shift register values with it 
//
// Here's how to calculate the CRC poly for a given generator polynomial:
// Write 1 where there's an x coefficient and write 0 when there's no x for a given power:
// 10001000000100001
// Cut the leftmost bit and convert it to a 16 bit hex number: 0x1021
// Algorithm source: http://srecord.sourceforge.net/crc16-ccitt.html
// *crc initial value should be 0xffff.
void crc_calc_crc16_ccitt(uint16_t *crc, uint8_t in) {
	uint8_t v;
	flag_t xor_flag;
	uint8_t i;

	v = 0x80;
	for (i = 0; i < 8; i++) {
		if ((*crc) & 0x8000)
			xor_flag = 1;
		else
			xor_flag = 0;

		(*crc) <<= 1;

		if (in & v)
			(*crc)++;

		if (xor_flag)
			(*crc) ^= 0x1021;

		v >>= 1;
	}
}

// Empties out the shift registers for the CRC calculation. Call this function when there's no more data left.
void crc_calc_crc16_ccitt_finish(uint16_t *crc) {
	flag_t xor_flag;
	uint8_t i;

	for (i = 0; i < 16; i++) {
		if ((*crc) & 0x8000)
			xor_flag = 1;
		else
			xor_flag = 0;

		(*crc) <<= 1;

		if (xor_flag)
			(*crc) ^= 0x1021;
	}
}

// G(x) = x^9+x^6+x^4+x^3+1 -> poly = 0b001011001 = 0x59
void crc_calc_crc9(uint16_t *crc, uint8_t in, uint8_t in_bitscount) {
	uint8_t v;
	flag_t xor_flag;
	uint8_t i;

	v = 0x80;
	for (i = 0; i < 8-in_bitscount; i++)
		v >>= 1;
	for (i = 0; i < 8; i++) {
		if ((*crc) & 0x0100)
			xor_flag = 1;
		else
			xor_flag = 0;

		(*crc) <<= 1;

		// Limit the number of shift registers to 9.
		*crc &= 0x01ff;

		if (in & v)
			(*crc)++;

		if (xor_flag)
			(*crc) ^= 0x59;

		v >>= 1;
	}
}

void crc_calc_crc9_finish(uint16_t *crc, uint8_t out_bitscount) {
	flag_t xor_flag;
	uint8_t i;

	for (i = 0; i < out_bitscount; i++) {
		if ((*crc) & 0x0100)
			xor_flag = 1;
		else
			xor_flag = 0;

		(*crc) <<= 1;

		// Limit the number of shift registers to 9.
		*crc &= 0x01ff;

		if (xor_flag)
			(*crc) ^= 0x59;
	}
}

void crc_calc_crc32(uint32_t *crc, uint8_t in) {
	uint8_t v;
	flag_t xor_flag;
	uint8_t i;

	v = 0x80;
	for (i = 0; i < 8; i++) {
		if ((*crc) & 0x80000000)
			xor_flag = 1;
		else
			xor_flag = 0;

		(*crc) <<= 1;

		if (in & v)
			(*crc)++;

		if (xor_flag)
			(*crc) ^= 0x04c11db7;

		v >>= 1;
	}
}

void crc_calc_crc32_finish(uint32_t *crc) {
	flag_t xor_flag;
	uint8_t i;

	for (i = 0; i < 32; i++) {
		if ((*crc) & 0x80000000)
			xor_flag = 1;
		else
			xor_flag = 0;

		(*crc) <<= 1;

		if (xor_flag)
			(*crc) ^= 0x04c11db7;
	}
}
