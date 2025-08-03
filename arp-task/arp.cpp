#include "arp.h"
#include "mac_addr.h"

total_Arp Arp_Request(char* sendip , char* reip,char* name){
    total_Arp packet;
    makeuint8_tmac(packet.eth_he.sou,name);
    for(int i=0;i<6;i++)
        packet.eth_he.des[i] = 0xFF;
    //여기 추가할 것.
	packet.eth_he.type = htons(0x0806);
    packet.arp_he.hw_type = htons(0x0001);
    packet.arp_he.pro_type = htons(0x0800); 
    packet.arp_he.hw_len = 6;                     
    packet.arp_he.pro_len = 4;                    
    packet.arp_he.opcode = htons(0x0001);    //0x0001는 ARP 요청 패킷
    
    //ip는 사실상 char으로 들어왔는데 어떻게 uint8_t로 넣지? 어떻게 하지?

    //inet_pton을 처음에 구현해보려고 했다가 어떻게 구현할지 감이 안 잡혀서 gpt에게 물어봤더니
    //gpt가 inet_pton을 사용해보라고 해서 사용했습니다.
    inet_pton(AF_INET, sendip, packet.arp_he.sip);
    makeuint8_tmac(packet.arp_he.smac,name);

    for(int i=0;i<4;i++)
        packet.arp_he.tmac[i] = 0x00;
    inet_pton(AF_INET, reip, packet.arp_he.tip);
    return packet;
}

void makeuint8_tmac(uint8_t* recv_mac, char* name){
    uint8_t* temp = make_my_mac(name);
    for(int i=0; i<6;i++)
        recv_mac[i] = temp[i];
}

//main에 있는 주석처럼 mac 주소를 받아오는 것을 구현해보려고 했는데 실패해서 GPT를 이용하여서 구현하였습니다.
//그래서 제가 이해하는 느낌으로 주석을 추가하겠습니다.
uint8_t* get_target_mac_by_arp(pcap_t* pcap, char* target_ip_str, total_Arp packet) {
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
		if (res == 0) continue; // timeout       //// res == 0: 패킷이 없어 타임 아웃이 나면 다음 루프로 계속 대기합니다.code 
		if (res == -1 || res == -2) break;      //-1, -2면 오류 대기이거나 루프 중단 요청이 나온 것 입니다.

		// Ethernet Type 검사
		if (ntohs(*(uint16_t*)(pkt + 12)) != 0x0806) continue; // ARP 패킷이 아니니까 다시 패킷을 받아온다.

		const u_char* arp_ptr = pkt + 14; //만약 arp 패키지면 pkt사이즈에 14를 추가 
		uint16_t opcode = ntohs(*(uint16_t*)(arp_ptr + 6)); //opcode도 확인하여 2중으로 확인합니다.
		if (opcode != 0x0002) continue; // ARP Reply 아님

		// sender MAC 저장
		static uint8_t target_mac[6]; // 위의 조건들을 다 통과하면 내가 보낸 패킷이 맞으니까 target_mac으로 설정하여서 저장한다.
		memcpy(target_mac, arp_ptr + 8, 6); // 그리고 memcpy로 내가 설정한 return을 할 수 있는 값으로 설정.
		return target_mac; //그리고 내가 보낸 패킷으로 얻은 mac 값을 return 할 수 있도록 설정하였다.

		if (time(nullptr) - start > 5) break; // timeout: 5초
	}

	fprintf(stderr, "[!] ARP Reply를 받지 못했습니다.\n");
	return nullptr;
}

void Arp_Reply(pcap_t* pcap, uint8_t* s_mac, char* sendip , char* reip,char* name ){
    total_Arp packet;
	//for문을 이용해서 값을 넣는 것이 많은데 이것도 함수화를 해야하나?
    makeuint8_tmac(packet.eth_he.sou,name);
	for(int i=0;i<6;i++)
        packet.eth_he.des[i] = s_mac[i];
    
	packet.eth_he.type = htons(0x0806); //0x0806은 arp 패킷의 타입.
    packet.arp_he.hw_type = htons(0x0001); //0x001은 하드웨어 타입
    packet.arp_he.pro_type = htons(0x0800); 
    packet.arp_he.hw_len = 6;                     
    packet.arp_he.pro_len = 4;                    
    packet.arp_he.opcode = htons(0x0002);    //0x0002는 ARP 응답 요청

    inet_pton(AF_INET, reip, packet.arp_he.sip);
    makeuint8_tmac(packet.arp_he.smac, name);

    for(int i=0;i<6;i++)
        packet.arp_he.tmac[i] = s_mac[i];
    inet_pton(AF_INET, sendip, packet.arp_he.tip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(total_Arp));
}
