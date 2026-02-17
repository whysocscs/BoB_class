#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

typedef struct eth {
	uint8_t des[6];
	uint8_t sou[6];
	uint16_t type;
} __attribute__ ((__packed__)) eth;

typedef struct ip {
	uint8_t ver;
	uint8_t Service_type;
	uint16_t Total_length;
	uint16_t Identification;
	uint16_t Flag_offset;
	uint8_t TTL;
	uint8_t Protocol;
	uint16_t Header_checksum;
	uint8_t sou[4];
	uint8_t des[4];
} __attribute__ ((__packed__)) ip;

typedef struct tcp {
	uint8_t sou[2];
	uint8_t des[2];
	uint32_t seq;
	uint32_t ack;
	uint16_t H_len;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} __attribute__ ((__packed__)) tcp;

typedef struct data {
	unsigned char data[20];
} __attribute__ ((__packed__)) data;

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		eth *eth_head = (eth *)packet;
		ip *ip_head = (ip *)(packet + sizeof(eth));
		tcp *tcp_head = (tcp *)(packet + sizeof(eth) + sizeof(ip));
		data *data_head = (data *)(packet + sizeof(eth) + sizeof(ip) + sizeof(tcp));

		if (ip_head->Protocol != 0x06 || ntohs(eth_head->type) != 0x0800)
			continue;

		printf("eth des : ");
		for (int i = 0; i < 6; i++)
			printf("%02x ", eth_head->des[i]);

		printf(" eth sou : ");
		for (int i = 0; i < 6; i++)
			printf("%02x ", eth_head->sou[i]);

		printf("\nip des  : ");
		for (int i = 0; i < 4; i++)
			printf("%02x ", ip_head->des[i]);

		printf("       ip sou  : ");
		for (int i = 0; i < 4; i++)
			printf("%02x ", ip_head->sou[i]);

		printf("\ntcp des : ");
		for (int i = 0; i < 2; i++)
			printf("%02x ", tcp_head->des[i]);

		printf("             tcp sou : ");
		for (int i = 0; i < 2; i++)
			printf("%02x ", tcp_head->sou[i]);

		printf("\ndata : ");
		int is_printable = 0;
		for (int i = 0; i < 4; i++) {
			if (data_head->data[i] == 0)
				is_printable++;
		}

		if (is_printable < 4) {
			for (int i = 0; i < 20; i++) {
				printf("%02x ", data_head->data[i]);
				data_head->data[i] = 0x00;
			}
		} else {
			for (int i = 0; i < 20; i++)
				printf("00 ");
		}

		printf("\n ------------------------------------------------------------\n");
	}

	pcap_close(pcap);
	return 0;
}
