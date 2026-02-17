#include <stdint.h>

typedef struct tcp {
	uint8_t sou[2];
	uint8_t des[2];
	uint32_t seq;
	uint32_t ack;
	uint8_t  RE:4;
    uint8_t  offset:4;
	uint16_t window;
	uint16_t checksum;
	uint16_t pointer;
} __attribute__ ((__packed__)) tcp;

