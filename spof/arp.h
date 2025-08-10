#pragma once
#include <pcap.h>
#include <time.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <vector>   
#include <stdlib.h>
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
struct ip_collection{
	uint32_t sendip;
	uint32_t targetip;
	uint8_t sendmac[6];
	uint8_t targetmac[6];
	uint8_t mymac[6];
};
total_Arp Arp_Request(uint32_t sendip , uint32_t reip,char* name);
void makeuint8_tmac(uint8_t* recv_mac, char* name);
uint8_t* get_target_mac_by_arp(pcap_t* pcap,uint32_t sender_ip ,uint32_t target_ip, total_Arp packet);
total_Arp Arp_Reply(uint32_t sender_ip ,uint8_t* s_mac, uint32_t target_ip, char* name );
void makecollet(ip_collection* collete, pcap_t* pcap, int cnt, char** argv, char *name);
void infect(ip_collection * collete, pcap_t * pcap, int cnt, char *name);
size_t receiveandsend(pcap_t* pcap, ip_collection* collect, int pair_cnt, char* name);