#pragma once
#include <iostream>
#include <array>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

struct tcp_hdr
{
    uint32_t number;
    uint32_t ack_number;
    uint16_t len:4, reserved:3, ns:1, cwr:1, ece:1, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1;
    uint16_t window_size;
    uint16_t SACK;
};

class Sender
{
private:
    // class Interface
    // {
    // private:
    // public:
    //     Interface();
    //     unsigned short calculate_checksum(const void* data, size_t length);
    //     iphdr * ipHeader() const;
    //     udphdr * udpHeader() const;
    //     char * data() const; 
    //     std::array<char, 1024> fillIpHeader();
    // } m_interf;
    char m_buffer[1024];
private:
    int m_sockfd;
    const std::string m_addr;
    int m_port;
    struct sockaddr_in m_servaddr;

public:
    Sender(std::string_view addr, int port);
    ~Sender();
    //SYN
    bool connect(); 
    //SACK
    bool send(std::initializer_list<char> data);

};