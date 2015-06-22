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

#ifndef TYPES_H_
#define TYPES_H_

#include <config/defaults.h>

#include <stdint.h>

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#define BE16_TO_CPU(x) Swap16(x)
#define BE32_TO_CPU(x) Swap32(x)
#define CPU_TO_BE16(x) Swap16(x)
#define CPU_TO_BE32(x) Swap32(x)

#define Swap16(u16) ((uint16_t)(((uint16_t)(u16) >> 8) |\
    ((uint16_t)(u16) << 8)))

#define Swap32(u32) ((uint32_t)(((uint32_t)Swap16((uint32_t)(u32) >> 16)) |\
    ((uint32_t)Swap16((uint32_t)(u32)) << 16)))

#define ASSERT(x) static uint8_t __attribute__((unused)) assert_var[(x) ? 1 : -1]

typedef char base_id_t[16]; // This have to fit into one EEPROM page (16 bytes by default).
typedef uint8_t flag_t;

typedef struct __attribute__((packed)) {
	uint8_t sigexit		: 1;
} base_flags_t;

#endif
