#pragma once
#include <stdint.h>

struct eth_h {
	uint8_t des[6];
	uint8_t sou[6];
	uint16_t type;
};