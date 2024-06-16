#include "Sender.hpp"
#include <cstring>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <condition_variable>


#define PORT 8080
#define SERVER_IP "127.0.0.1"

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
    this->window_size = other.window_size;
    this->from_serv = other.from_serv;
    this->SACK = other.SACK;
    return *this;
}

tcp_hdr::tcp_hdr() : number(0), ack_number(0), len(0), reserved(0), ns(0), cwr(0), ece(0), fin(0),
                    syn(0), rst(0), psh(0), urg(0), window_size(0), from_serv(0), SACK(0)
{
}

static unsigned short calculate_checksum(void* b, size_t len)
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

static uint32_t generate_isn() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

    std::mt19937_64 rng(nanos);
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

    return dist(rng);
}

Interface::Interface() : trueOrFalseCond(false), m_bytes(0){}

Interface::Interface(const unsigned char* packet) : trueOrFalseCond(false), m_bytes(0)
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
    memcpy(&(this->m_buffer), other, sizeof(pars));
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

Sender::Sender(std::string_view addr, int port) : m_addr(addr), m_port(port),
        m_sizeheaders(sizeof(struct udphdr)+ sizeof(struct tcp_hdr)), stop_timer(false), isStoped(false),
        m_number(1)

{
    std::cout << "Sender::Sender()" << std::endl;
    if ((m_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    m_servaddr.sin_family = AF_INET;
    m_servaddr.sin_addr.s_addr = inet_addr(addr.data());
    m_servaddr.sin_port = htons(m_port);

    if (inet_pton(AF_INET, SERVER_IP, &m_servaddr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    m_tv.tv_sec = 5;
    m_tv.tv_usec = 0;
    if (setsockopt(m_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&m_tv, sizeof(m_tv)) < 0) {
        std::cerr << "Error setting socket options" << std::endl;
    }

    std::cout << "generated isn - " << m_number << std::endl;
    std::cout << "sizeof pseudo - " << sizeof(pseudo_header) << std::endl;
}

std::array<char, 1024> Sender::create_packet(const struct tcp_hdr* tcp, const char* data, int data_size)
{
    std::array<char, 1024> packet;
    packet.fill('\0');

    pseudo_header * ps = (struct pseudo_header *)packet.begin();
    ps->dest_address = inet_addr(m_addr.c_str());
    ps->source_address = inet_addr(m_addr.c_str());
    ps->placeholder = 0;
    ps->protocol = IPPROTO_UDP;
    ps->udp_length = sizeof(struct udphdr);

    struct udphdr * ud = (struct udphdr *)(std::next(packet.begin(), sizeof(struct pseudo_header)));
    ud->source = htons(m_port);
    ud->dest = htons(m_port);
    ud->len = htons(sizeof(struct udphdr));
    ud->check = 0;

    struct tcp_hdr * tc = (struct tcp_hdr *)(std::next(packet.begin(), sizeof(struct pseudo_header) + sizeof(struct udphdr)));
    *tc = *tcp;

    memcpy(std::next(packet.begin(), sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct tcp_hdr)),data, data_size);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_size;

    ud->check = htons(calculate_checksum(packet.data(), psize));
    std::cout << "checksum - " << ntohs(ud->check) << std::endl;
    return packet;
}
 
Interface* Sender::recieve() {
    socklen_t addrlen = sizeof(m_servaddr);
    char buffer[1024];
    Interface *inter;

    for(int i = 0; i <= 3; ++i)
    {
        int n = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&m_servaddr, &addrlen);
        if(n > 0)
        {
            inter = new Interface((unsigned char *)buffer);
            if(inter->tcpHeader()->from_serv == 1)
            {
                inter->setByte(n);
                *inter = true;
                return inter;
            }
        }
        else
        {
            *inter = false;
            std::cout << "nooo\n";
        }
    }
    *inter = false;
    return inter;
}

bool Sender::connect()
{
    const char *message = "Hello, Server!\0";
    int message_len = strlen(message);
    tcp_hdr * tcp = new tcp_hdr;
    tcp->number = ntohs(m_number);
    tcp->ack_number = 0;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->from_serv = 0;
    tcp->window_size = htons(message_len);

    auto packet = create_packet(tcp, message, message_len);
    int d;
    std::cout << "ack_packet - " << htons(tcp->ack_number) << std::endl;
    std::cout << "number - " << htons(tcp->number) << std::endl;
    if ((d = sendto(m_sockfd, std::next(packet.begin(), sizeof(struct pseudo_header)), m_sizeheaders + message_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr))) < 0) {
        perror("sendto failed");
    } else {
        std::cout << "Message sent to server. "  << d << "  " << message_len << std::endl;
    }
    
    char buffer[1024];
    socklen_t addrlen = sizeof(m_servaddr);
    auto interface = recieve();
    if (interface) {
        std::cout << "Server reply received." << std::endl;
        if (interface->tcpHeader()->syn == 1 && interface->tcpHeader()->ack == 1) {
            std::cout << "Received SYN-ACK from server." << std::endl;
            std::cout << "recieved ack_packet - " << ntohs(interface->tcpHeader()->ack_number) << std::endl;
            std::cout << "recieved number - " << ntohs(interface->tcpHeader()->number) << std::endl;
            // Send ACK to complete three-way handshake
            m_number = ntohs(interface->tcpHeader()->ack_number);
            char * jjj = "helodsdsds ack\0";
            tcp_hdr *ack_tcp = new tcp_hdr();
            ack_tcp->ack = 1;
            ack_tcp->number = htons(m_number);
            ack_tcp->ack_number = htons(ntohs(interface->tcpHeader()->number) + interface->getByte() + 1);
            ack_tcp->syn = 0;
            ack_tcp->from_serv = 0;
            ack_tcp->window_size = htons(strlen(jjj));

            std::cout << "sending number - " << ntohs(ack_tcp->number) << std::endl;
            std::cout << "sending ack number - " << ntohs(ack_tcp->ack_number) << " len -  " << interface->getByte() <<  std::endl;

            auto ack_packet = create_packet(ack_tcp, jjj, strlen(jjj));
            //std::cout << "here - "<< ntohl(interface->tcpHeader()->number) << "than there - " <<  ntohl(interface->tcpHeader()->number) + 1 << std::endl;
            if (sendto(m_sockfd, std::next(ack_packet.begin(), sizeof(struct pseudo_header)), m_sizeheaders + strlen(jjj), 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
                perror("sendto failed");
            } else {
                std::cout << "ACK sent to server." << std::endl;
                std::cout << "data - " << reinterpret_cast<char *>(std::next(ack_packet.begin(), 36)) << std::endl;
                std::cout << "size - " << strlen(reinterpret_cast<char *>(std::next(ack_packet.begin(), 36))) << std::endl;
                // std::cout << "ack - " << reinterpret_cast<tcp_hdr*>(std::next(ack_packet.begin(), 20))->ack << std::endl;
                // std::cout << "syn - " << reinterpret_cast<tcp_hdr*>(std::next(ack_packet.begin(), 20))->syn << std::endl;
            }
        }
    } else {
        perror("recvfrom failed");
        std::cout << "recvfrom failed with error code: " << errno << std::endl;
    }
    return true;
}

//no sack implementation
bool Sender::send(const char * packet)
{
    std::cout << "Sender::send()" << std::endl;
    auto data_len = strlen(packet);
    tcp_hdr * tc = new tcp_hdr();
    tc->from_serv = 0;
    tc->ack = 0;
    tc->number = htons(m_number);
    tc->SACK = 0;
    tc->window_size = htons(data_len);
    auto pack = create_packet(tc, std::move(packet), data_len);

    int n = sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + data_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
    if(n > 0)
    {
        std::cout << "send Success " << std::endl;
        auto interf = recieve();

        std::cout << "recieved ack send() - " << ntohs(interf->tcpHeader()->ack_number) << " m_number - " << m_number << std::endl; 

        if(interf->tcpHeader()->ack == 1 && ntohs(interf->tcpHeader()->ack_number) - m_number == (m_sizeheaders + data_len + 20) + 1)
        {
            std::cout << "packet has been ack " << std::endl;
            return true;
        }
        else
        {
            std::cout << "else " << std::endl;
        }

        // if(interf){ std::cout << "resending ...\n"; send(packet); }
    }
    return false;
}

//sack implementation
bool Sender::send(std::initializer_list<char *> packets)
{
    // need message, that tell to the server, that we will use sack

    for(size_t i = 0; i < packets.size(); ++i)
    {
        // auto len = strlen(packets[i]);
        // auto tcp = std::make_shared<tcp_hdr>();
        // tcp->number = htons(m_number + i);
        // tcp->SACK = 1;
        // tcp->from_serv = 0;
        // tcp->window_size = htons(len);

        // auto pack = create_packet(tcp, packets[i], len);
        // sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + len ,0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
    }
}


    // std::condition_variable cv;
    // std::mutex cv_m;
    // stop_timer = false;
    // isStoped = false;

//void timer(std::atomic<bool>& stop_timer, std::condition_variable& cv, std::mutex& cv_m, std::atomic<bool>& isStoped)
// {
//     std::unique_lock<std::mutex> lk(cv_m);
//     while (true) {
//         if (cv.wait_for(lk, std::chrono::seconds(15), [&]{ return stop_timer.load(); })) {
//             std::cout << "Timer stopped!\n";
//             break;
//         } else {
//             isStoped = true;
//             break;
//         }
//     }
// }
