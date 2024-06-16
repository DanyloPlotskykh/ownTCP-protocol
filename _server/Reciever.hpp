#pragma once
#include <queue>
#include <array>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string>

#define BUFFER_SIZE 1024

struct tcp_hdr
{
    uint32_t number;
    uint32_t ack_number;
    uint16_t len:4, reserved:3, ns:1, cwr:1, ece:1, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1;
    uint16_t window_size;
    uint16_t from_serv;
    uint16_t SACK;

    tcp_hdr& operator=(const tcp_hdr& other) noexcept;
    tcp_hdr();
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
    std::array<char, BUFFER_SIZE> m_buffer;
    bool trueOrFalseCond;
    int m_bytes;
public:
    explicit Interface(const char* packet);
    ~Interface();
    iphdr * ipHeader();
    udphdr * udpHeader();
    tcp_hdr * tcpHeader();
    char * data();
    
    std::array<char, BUFFER_SIZE> getPacket() const;
    void setByte(int n);
    int getByte() const;
    
    Interface& operator=(const bool other);
    operator bool() const;
    bool operator!() const;
};

class Reciever {
private:
    const int m_sizeheaders;
    std::string m_addr;
    std::queue<Interface> m_window;
    int m_number;
    int m_sockfd;
    int m_port;
    struct sockaddr_in m_servaddr, m_cliaddr;
    socklen_t m_len;
    std::array<char, BUFFER_SIZE> create_packet(const struct tcp_hdr* tcp, const char* data, int data_size);

private:
    Interface* recieve();
public:
    Reciever();
    ~Reciever();
    bool connect();
    void accept();
};