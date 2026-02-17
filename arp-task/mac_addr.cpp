#include "mac_addr.h"


uint8_t* make_my_mac(char* name) {
    static uint8_t mac[6];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sockfd);
        return NULL;
    }

    close(sockfd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return mac;
}