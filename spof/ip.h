#pragma once
#include <stdint.h>

typedef struct ip {
	uint8_t len:4;
    uint8_t ver:4;
	uint8_t type;
	uint16_t Total_length;
	uint16_t ID;
	uint16_t Flag_offset;
	uint8_t TTL;
	uint8_t Proto;
	uint16_t checksum;
	uint8_t sou[4];
	uint8_t des[4];
}  ip;
