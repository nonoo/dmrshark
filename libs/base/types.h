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
