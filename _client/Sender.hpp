#pragma once
#include <iostream>
#include <array>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <vector>

#include "tools.hpp"

class Sender
{
private:
    const int m_sizeheaders;
    int m_sockfd;
    const std::string m_addr;
    const int m_port;
    uint32_t m_number;
    struct sockaddr_in m_servaddr;
    struct timeval m_tv;
    socklen_t m_len;
    int m_prevPackNumber;

private:
    Interface* recieve();
    std::array<char, 1024> create_packet(const struct tcp_hdr* tcp, const char* data, int data_size);

public:
    Sender(std::string_view addr, int port);
    //SYN-ACK
    bool connect();  // where?? connect to what??
    //SACK
    bool send(std::vector<char *> packets);
    //no-sack
    bool send(const char* packet, int number = -1);

    //in future FIN
    // fin();

    void accept();
    // void accept1();
};