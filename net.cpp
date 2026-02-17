#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char *block_host = NULL;

struct ip_header {
    unsigned char version_ihl;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int source_addr;
    unsigned int dest_addr;
};

struct tcp_header {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

void dump(unsigned char* buf, int size) {
    int i;
    printf("=== Packet Dump ===\n");
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n==================\n");
}

char* extract_host(char* http_data, int data_len) {
    char* host_line = NULL;
    char* host_start = NULL;
    char* host_end = NULL;
    static char host_buffer[256];
    
    char* temp_data = malloc(data_len + 1);
    if (!temp_data) return NULL;
    
    memcpy(temp_data, http_data, data_len);
    temp_data[data_len] = '\0';
    
    host_line = strcasestr(temp_data, "Host:");
    if (!host_line) {
        free(temp_data);
        return NULL;
    }
    
    host_start = host_line + 5;
    while (*host_start == ' ' || *host_start == '\t') {
        host_start++;
    }
    
    host_end = host_start;
    while (*host_end != '\r' && *host_end != '\n' && *host_end != '\0' && 
           (host_end - temp_data) < data_len) {
        host_end++;
    }
    
    int host_len = host_end - host_start;
    if (host_len > 0 && host_len < 255) {
        memcpy(host_buffer, host_start, host_len);
        host_buffer[host_len] = '\0';
        
        char* colon = strchr(host_buffer, ':');
        if (colon) {
            *colon = '\0';
        }
        
        free(temp_data);
        return host_buffer;
    }
    
    free(temp_data);
    return NULL;
}

int analyze_packet(unsigned char* data, int len) {
    struct ip_header* ip_hdr;
    struct tcp_header* tcp_hdr;
    char* http_data;
    char* host;
    
    printf("=== Packet Analysis ===\n");
    printf("Total packet length: %d bytes\n", len);
    
    if (len < sizeof(struct ip_header)) {
        printf("Packet too small for IP header\n");
        return 0;
    }
    
    ip_hdr = (struct ip_header*)data;
    
    if ((ip_hdr->version_ihl >> 4) != 4) {
        printf("Not IPv4 packet\n");
        return 0;
    }
    
    if (ip_hdr->protocol != 6) {
        printf("Not TCP packet (protocol: %d)\n", ip_hdr->protocol);
        return 0;
    }
    
    int ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;
    printf("IP header length: %d bytes\n", ip_hdr_len);
    
    if (len < ip_hdr_len + sizeof(struct tcp_header)) {
        printf("Packet too small for TCP header\n");
        return 0;
    }
    
    tcp_hdr = (struct tcp_header*)(data + ip_hdr_len);
    
    if (ntohs(tcp_hdr->dest_port) != 80 && ntohs(tcp_hdr->source_port) != 80) {
        printf("Not HTTP traffic (src: %d, dst: %d)\n", 
               ntohs(tcp_hdr->source_port), ntohs(tcp_hdr->dest_port));
        return 0;
    }
    
    printf("HTTP traffic detected (src: %d, dst: %d)\n", 
           ntohs(tcp_hdr->source_port), ntohs(tcp_hdr->dest_port));
    
    int tcp_hdr_len = (tcp_hdr->data_offset >> 4) * 4;
    printf("TCP header length: %d bytes\n", tcp_hdr_len);
    
    int total_hdr_len = ip_hdr_len + tcp_hdr_len;
    if (len <= total_hdr_len) {
        printf("No HTTP data payload\n");
        return 0;
    }
    
    http_data = (char*)(data + total_hdr_len);
    int http_data_len = len - total_hdr_len;
    
    printf("HTTP data length: %d bytes\n", http_data_len);
    
    if (http_data_len < 4 || 
        (strncmp(http_data, "GET ", 4) != 0 && 
         strncmp(http_data, "POST", 4) != 0 &&
         strncmp(http_data, "HEAD", 4) != 0)) {
        printf("Not HTTP request\n");
        return 0;
    }
    
    printf("HTTP request detected\n");
    
    host = extract_host(http_data, http_data_len);
    if (host) {
        printf("Host: %s\n", host);
        
        if (strcmp(host, block_host) == 0) {
            printf("*** BLOCKED HOST DETECTED: %s ***\n", host);
            return 1;
        }
    } else {
        printf("Host field not found\n");
    }
    
    printf("======================\n");
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *packet_data;
    int verdict = NF_ACCEPT;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("\n=== Processing packet ID: %u ===\n", id);
    }
    
    ret = nfq_get_payload(nfa, &packet_data);
    if (ret >= 0) {
        printf("Payload length: %d bytes\n", ret);
        
        if (analyze_packet(packet_data, ret)) {
            verdict = NF_DROP;
            printf("VERDICT: DROP\n");
        } else {
            verdict = NF_ACCEPT;
            printf("VERDICT: ACCEPT\n");
        }
        
        if (ret < 200) {
            dump(packet_data, ret);
        }
    } else {
        printf("Failed to get payload\n");
    }
    
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    // 명령행 인자 확인
    if (argc != 2) {
        printf("syntax : %s <host>\n", argv[0]);
        printf("sample : %s test.gilgil.net\n", argv[0]);
        exit(1);
    }
    
    block_host = argv[1];
    printf("Blocking host: %s\n", block_host);
    
    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }
    
    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }
    
    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }
    
    printf("Binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }
    
    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }
    
    fd = nfq_fd(h);
    
    printf("Ready to process packets. Press Ctrl+C to exit.\n");
    printf("========================================\n");
    
    // 메인 루프
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        
        if (rv < 0 && errno == ENOBUFS) {
            printf("Losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }
    
    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    
    printf("Closing library handle\n");
    nfq_close(h);
    
    return 0;
}
