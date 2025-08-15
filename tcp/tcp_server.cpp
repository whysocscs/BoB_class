#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct Param {
    bool     echo{false};
    bool     brod{false};
    uint16_t port{0};

    bool parse(int argc, char* argv[]) {
        for (int i = 1; i < argc;) {
            if (std::strcmp(argv[i], "-e") == 0) {
                echo = true; ++i; continue;
            }
            if (std::strcmp(argv[i], "-b") == 0) {
                brod = true; ++i; continue;
            }
            // 위치 인자: 포트
            port = static_cast<uint16_t>(std::atoi(argv[i++]));
        }
        return port != 0;
    }
} param;

struct std::vector<int> clients;
struct std::mutex       mtx;

static ssize_t send(int sd, const char* data, size_t len){
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(sd, data + sent, len - sent, 0);
        if (n <= 0) return n;                  
        sent += static_cast<size_t>(n);        
    }
    return static_cast<ssize_t>(sent);
}

static void broadcast(const char* data, size_t len){
    std::string msg = std::string("broadcast: ") + std::string(data, len);
    std::lock_guard<std::mutex> lock(mtx);
    for (auto it = clients.begin(); it != clients.end();) {
        int sd = *it;
        ssize_t n = send(sd, msg.data(), msg.size());
        if (n <= 0) { ::close(sd); it = clients.erase(it); }
        else        { ++it; }
    }
}

static void recvThread(int sd) {
    static int BUFSIZE = 4096;
    char buf[BUFSIZE];

    while (true) {
        ssize_t r = ::recv(sd, buf, BUFSIZE - 1, 0);
        if (r <0 ) {
            perror("recv");
            break;
        }
        buf[r] = '\0';
        std::printf("%s", buf);
        std::fflush(stdout);

        if (param.brod) 
            broadcast(buf, static_cast<size_t>(r));
        else if (param.echo) {
            // 에코: "server: " 접두어
            std::string msg = std::string("server: ") + std::string(buf, r);
            if (send(sd, msg.data(), msg.size()) <= 0) break;
        }
    }

    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = std::find(clients.begin(), clients.end(), sd);
        if (it != clients.end()) 
            clients.erase(it);
    }
    ::close(sd);
    std::puts("disconnected");
}

static void usage(){
    std::printf("Usage:  <port> [-e] [-b]\n");
    std::printf("  -e : echo (보낸 클라이언트에게만 회신)\n");
    std::printf("  -b : broadcast (접속된 모든 클라이언트에게 전송)\n");
    std::printf("  ※ -b가 주어지면 -e보다 우선합니다.\n");
}

int main(int argc, char* argv[]) {
    if (!param.parse(argc, argv)) {
        usage();
        return -1;
    }

    // socket
    int sd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1) { std::perror("socket"); return -1; }

    {
        int on = 1;
        if (::setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            std::perror("setsockopt(SO_REUSEADDR)");
            ::close(sd);
            return 1;
        }
    }
    printf("Server listening on port %d\n", param.port);
    // bind
    {
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(param.port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        int res = ::bind(sd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (res == -1) {
            std::perror("bind");
            ::close(sd);
            return -1;
        }
    }

    // listen
    {
        int res = ::listen(sd, 5);
        if (res == -1) {
            std::perror("listen");
            ::close(sd);
            return -1;
        }
    }

    // accept loop
    while (true) {
        struct sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        int newsd = ::accept(sd, reinterpret_cast<struct sockaddr*>(&caddr), &clen);
        if (newsd == -1) {
            std::perror("accept");
            break;
        }
        {
            std::lock_guard<std::mutex> lock(mtx);
            clients.push_back(newsd);
        }
        std::thread(recvThread, newsd).detach();
    }

    ::close(sd);
    return 0;
}
