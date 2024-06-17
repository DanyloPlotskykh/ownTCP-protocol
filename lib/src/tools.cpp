#include <tools.hpp>
#include <chrono>
#include <random>
#include <cstring>
#include <iostream>

#define PORT 8080

tcp_hdr tcp_hdr::operator=(const tcp_hdr& other) noexcept
{
    if (this == &other) {
        return *this;
    }
    this->number = other.number;
    this->ack_number = other.ack_number;
    this->len = other.len;
    this->reserved = other.reserved;
    this->ns = other.ns;
    this->cwr = other.cwr;
    this->ece = other.ece;
    this->fin = other.fin;
    this->syn = other.syn;
    this->rst = other.rst;
    this->psh = other.psh;
    this->ack = other.ack;
    this->urg = other.urg;
    this->count_packets = other.count_packets;
    this->window_size = other.window_size;
    this->from_serv = other.from_serv;
    this->SACK = other.SACK;
    return *this;
}

tcp_hdr::tcp_hdr() : number(0), ack_number(0), len(0), reserved(0), ns(0), cwr(0), ece(0), fin(0),
                    syn(0), rst(0), psh(0), urg(0), window_size(0), from_serv(0), SACK(0), count_packets(0)
{
}

uint32_t generate_isn() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

    std::mt19937_64 rng(nanos);
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

    return dist(rng);
}

unsigned short calculate_checksum(void* b, size_t len)
{
    unsigned short *buf = reinterpret_cast<unsigned short *>(b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

bool verify_checksum(const char* packet, int packet_len, const char* src_ip, const char* dest_ip) 
{
    if (packet_len < 0)
        return false;
    
    std::array<char, BUFFER_SIZE> array;
    auto interf = Interface(packet);
    auto recieved = ntohs(interf.udpHeader()->check);
    auto data_size = strlen(interf.data());
    
    std::cout << "recieved checksum - " << recieved << std::endl;

    pseudo_header * ps = (struct pseudo_header * )array.begin();
    ps->dest_address = inet_addr("127.0.0.1");
    ps->source_address = inet_addr("127.0.0.1");
    ps->placeholder = 0;
    ps->protocol = IPPROTO_UDP;
    ps->udp_length = sizeof(struct udphdr);

    struct udphdr * ud = (struct udphdr *)(std::next(array.begin(), sizeof(pseudo_header)));
    ud->dest = htons(PORT);
    ud->source = htons(PORT);
    ud->len = htons(sizeof(struct udphdr));
    ud->check = 0;

    struct tcp_hdr * tc = (struct tcp_hdr *)(std::next(array.begin(), sizeof(pseudo_header) + sizeof(struct udphdr)));
    *tc = *(interf.tcpHeader());

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct tcp_hdr) + ntohs(interf.tcpHeader()->window_size);

    memcpy(std::next(array.begin(), sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct tcp_hdr)), interf.data(), data_size);
    auto control = calculate_checksum(array.data(), psize);

    std::cout << "calculated checksum - " << control << std::endl;

    return (control == recieved);
}

Interface::Interface() : trueOrFalseCond(false), m_bytes(0){}

Interface::Interface(const char* packet) : trueOrFalseCond(false), m_bytes(0)
{
    memcpy(m_buffer.data(), packet, m_buffer.size());
}

Interface::~Interface()
{
    std::cout << "Interface::~Interface()" << std::endl;
}

iphdr * Interface::ipHeader()
{
    return reinterpret_cast<iphdr * >(m_buffer.begin());
}

udphdr * Interface::udpHeader() 
{
    return reinterpret_cast<udphdr *>(std::next(m_buffer.begin(), sizeof(iphdr)));
}
tcp_hdr * Interface::tcpHeader() 
{
    return reinterpret_cast<tcp_hdr *>(std::next(m_buffer.begin(), sizeof(iphdr) + sizeof(udphdr)));
}

char * Interface::data()
{
    return reinterpret_cast<char *>(m_buffer.begin() + sizeof(iphdr) + sizeof(udphdr) + sizeof(tcp_hdr));
}

Interface& Interface::operator=(const bool other)
{
    this->trueOrFalseCond = other;
    return *this;
}

Interface& Interface::operator=(const char * other)
{
    memcpy(&(this->m_buffer), other, sizeof(other));
    return *this;
}

Interface::operator bool() const
{
    return trueOrFalseCond;
}

bool Interface::operator!() const 
{
    return !trueOrFalseCond;
}

void Interface::setByte(int n)
{
    this->m_bytes = n;
}

std::array<char, BUFFER_SIZE> Interface::getPacket() const
{
    return m_buffer;
} 

int Interface::getByte() const 
{
    return m_bytes;
}