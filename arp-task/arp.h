#pragma once
#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "mac_addr.h"
#include "eth.h"

struct arp_h {
	uint16_t hw_type;
	uint16_t pro_type;
	uint8_t hw_len;
	uint8_t pro_len;
	uint16_t opcode;
    uint8_t smac[6];
	uint8_t sip[4];
	uint8_t tmac[6];
	uint8_t tip[4];
};
struct total_Arp {
	eth_h eth_he;
	arp_h arp_he;
};

total_Arp Arp_Request(char* sendip , char* reip,char* name);
void Arp_Reply(pcap_t* pcap ,uint8_t* s_mac,char* sendip , char* reip,char* name );
void makeuint8_tmac(uint8_t* recv_mac, char* name);
uint8_t* get_target_mac_by_arp(pcap_t* pcap, char* target_ip_str, total_Arp packet);
