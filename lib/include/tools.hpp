#pragma once
#include <array>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <vector>

// static constexpr auto BUFFER_SIZE = 1024;
#define BUFFER_SIZE 1024 // don't use defines for such variables

struct tcp_hdr
{
    uint32_t number;
    uint32_t ack_number;
    uint16_t len:4, reserved:3, ns:1, cwr:1, ece:1, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1;
    uint16_t count_packets;
    uint16_t window_size;
    uint16_t from_serv;
    uint16_t SACK;

    tcp_hdr operator=(const tcp_hdr& other) noexcept;
    tcp_hdr();
};

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};


// improve naming
class Interface
{
private:
    std::array<char, 1024> m_buffer;
    bool trueOrFalseCond;
    int m_bytes;
public:
    // size of char *
    explicit Interface(const char* packet);
    Interface();
    ~Interface();
    iphdr * ipHeader();
    udphdr * udpHeader();
    tcp_hdr * tcpHeader();
    char * data();

    std::array<char, BUFFER_SIZE> getPacket() const;
    void setByte(int n);
    int getByte() const;

    // what it does?
    Interface& operator=(const bool other);
    Interface& operator=(const char * other);
    operator bool() const;
    bool operator!() const; // extra bool operator is enough
};

uint32_t generate_isn();
unsigned short calculate_checksum(void* b, size_t len);

bool verify_checksum(const char* packet, int packet_len, const char* src_ip, const char* dest_ip);
