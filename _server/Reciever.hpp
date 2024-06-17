#pragma once
#include <array>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string>
#include <vector>

#include "tools.hpp"

class Reciever {
private:
    const int m_sizeheaders;
    std::string m_addr;
    int m_number;
    int m_sockfd;
    int m_port;
    struct sockaddr_in m_servaddr, m_cliaddr;
    socklen_t m_len;
    bool m_sack;
    int m_prevPackNumber;

private:
    std::array<char, BUFFER_SIZE> create_packet(const struct tcp_hdr* tcp, const char* data, int data_size);
    Interface* recieve();

public:
    Reciever();
    ~Reciever();
    bool connect();
    void accept();
};