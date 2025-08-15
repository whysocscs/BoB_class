
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <iostream>

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static ssize_t send_all(int sd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(sd, data + sent, len - sent, 0);
        if (n <= 0) return n;           // 에러(-1) 또는 0 → 즉시 종료
        sent += static_cast<size_t>(n); // 누적
    }
    return static_cast<ssize_t>(sent);
}

static void recv_thread(int sd) {
    constexpr int BUFSIZE = 4096;
    char buf[BUFSIZE];

    while (true) {
        ssize_t r = ::recv(sd, buf, BUFSIZE, 0);
        if (r <= 0) {
            if (r < 0) std::perror("recv");
            break;
        }
        std::fwrite(buf, 1, static_cast<size_t>(r), stdout);
        std::fflush(stdout);
    }
    ::close(sd);
    std::exit(0); 
}

static void usage(const char* prog) {
    std::printf("Usage: %s <server_ip> <port>\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(argv[0]); return 1; }
    const char* ip = argv[1];
    uint16_t port = static_cast<uint16_t>(std::atoi(argv[2]));

    int sd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1) { std::perror("socket"); return 1; }

    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(port);
    if (::inet_pton(AF_INET, ip, &saddr.sin_addr) != 1) {
        std::fprintf(stderr, "invalid IPv4 address\n");
        ::close(sd);
        return 1;
    }
    if (::connect(sd, reinterpret_cast<sockaddr*>(&saddr), sizeof(saddr)) < 0) {
        std::perror("connect");
        ::close(sd);
        return 1;
    }
    std::printf("Connected to %s:%d\n", ip, port);
    
    std::thread(recv_thread, sd).detach();

    std::string line;
    while (std::getline(std::cin, line)) {
        line.push_back('\n');
        if (send_all(sd, line.data(), line.size()) <= 0) {
            std::perror("send");
            break;
        }
    }

    ::close(sd);
    return 0;
}
