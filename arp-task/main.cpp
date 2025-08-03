#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <pcap.h>
#include "arp.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "mac_addr.h"

int main(int argc, char *argv[]){
    if(argc < 2){
        printf("인자 개수 확인 요망");
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE]; //멘토님의 코드를 보고 사용했습니다.
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", pcap, errbuf);
        return 1;
    }
    uint8_t* know_tmac;
    total_Arp packet;

    for(int i=2; i< argc; i=i+2){
        char* sender_ip = argv[i];
        char* target_ip = argv[i+1];

        packet = Arp_Request(sender_ip, target_ip, argv[1]);

        know_tmac = get_target_mac_by_arp(pcap, argv[i+1],packet);

        Arp_Reply(pcap, know_tmac,sender_ip, target_ip, argv[1]);
    }
    
    // pcap_sendpacket을 보내고 그 뒤에 reply를 어떻게 받는지 몰라서 진짜 다 패킷을 뜯어서 확인해봐야하나?
    // 여러 가지 고민을 하다가 gpt를 사용하였습니다.

}
