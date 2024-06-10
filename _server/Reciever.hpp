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
    uint16_t SACK;

    tcp_hdr& operator=(const tcp_hdr& other);
};
 
struct pars
{
    struct iphdr ip;
    // struct udphdr udp;
    struct tcp_hdr tcp;
};

class Interface
{
private:
    std::array<char, 1024> m_buffer;
    pars p;
public:
    explicit Interface(const char* packet);
    ~Interface();
    iphdr ipHeader() const;
    udphdr udpHeader() const;
    tcp_hdr tcpHeader() const;
    char * data() const;
};

class Reciever {
private:
    const int m_sizeheaders;
    std::string m_addr;
    std::queue<Interface> m_window;
    int ack;
    int byte;
    int m_sockfd;
    int m_port;
    struct sockaddr_in m_servaddr, m_cliaddr;
    std::array<char, 1024> create_packet(const struct tcp_hdr& tcp, const char* data, int data_size);
public:
    Reciever();
    ~Reciever();
    int accept();
};