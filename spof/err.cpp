#include "err.h"

pcap_t* ReturnPcap(int cnt,char* name){
    if(cnt < 2){
        printf("인자 개수 확인 요망");
        exit(1);
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(name, BUFSIZ, 1, 1, errbuf);
     if (pcap == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", pcap, errbuf);
        exit(1);
    }
    return pcap;
}