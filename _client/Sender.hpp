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
    uint16_t from_serv;
    uint16_t SACK;

    tcp_hdr& operator=(const tcp_hdr& other);
};

struct pars
{
    struct iphdr ip;
    struct udphdr udp;
    struct tcp_hdr tcp;
};

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

class Interface
{
private:
    std::array<char, 1024> m_buffer;
    pars p;
    bool trueOrFalseCond;
public:
    explicit Interface(const char* packet);
    Interface();
    ~Interface();
    iphdr ipHeader() const;
    udphdr udpHeader() const;
    tcp_hdr tcpHeader() const;

    Interface& operator=(const bool other);
    Interface& operator=(const char * other);
    operator bool() const;
    bool operator!() const;
};

class Sender
{
private:
    const int m_sizeheaders;
    int m_sockfd;
    const std::string m_addr;
    int m_port;
    struct sockaddr_in m_servaddr;
    std::array<char, 1024> create_packet(const struct tcp_hdr& tcp, const char* data, int data_size);

private:
    Interface* recieve();

public:
    Sender(std::string_view addr, int port);
    //SYN
    bool connect(); 
    //SACK
    bool send(std::initializer_list<char *> packets);

};