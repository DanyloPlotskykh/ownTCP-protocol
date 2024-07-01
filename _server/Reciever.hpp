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
    const int m_sizeheaders; // static
    std::string m_addr;
    int m_number; // improve naming
    int m_sockfd;
    int m_port;
    struct sockaddr_in m_servaddr, m_cliaddr;
    socklen_t m_len;
    int m_prevPackNumber;

private:
    // Do you really need tcp header here?
    std::array<char, BUFFER_SIZE> create_packet(const struct tcp_hdr* tcp, const char* data, int data_size);
    Interface* recieve();

    // create_packet(data, size) -> _create_packet(2 params)
    // create_ACK_packet(....) -> _create_packet(6 params)s
    // _create_packet(param1, param2, param3, param4, param5, param6)

public:
    Reciever();
    ~Reciever();
    bool connect();
    void accept();

    // better to call it `data`
    bool send(const char* packet, int number = -1);
    bool send(std::vector<char *> packets);
    // for(const auto& packet: packets ){
        // send(packet);
    // /}
    // Why user should divide it's message on parts?
};