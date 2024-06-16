#include "Reciever.hpp"

#include <cstring>
#include <memory>
#include <iostream>
#include <chrono>
#include <random>
#include <iterator>
#include <thread>

#define PORT 8080

tcp_hdr& tcp_hdr::operator=(const tcp_hdr& other) noexcept
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
                    syn(0), rst(0), psh(0), urg(0), window_size(0), from_serv(1), SACK(0)
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

static bool verify_checksum(const char* packet, int packet_len, const char* src_ip, const char* dest_ip) 
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

static uint32_t generate_isn() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

    std::mt19937_64 rng(nanos);
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

    return dist(rng);
}

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

Reciever::Reciever() : m_addr("127.0.0.1"), m_number(2), m_sockfd(-1), m_port(8080), m_len(0),
    m_sizeheaders(sizeof(struct udphdr) + sizeof(struct tcp_hdr))
{
    std::cout << "Reciever::Reciever()" << std::endl;
    if ((m_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&m_servaddr, 0, sizeof(m_servaddr));
    memset(&m_cliaddr, 0, sizeof(m_cliaddr));

    m_servaddr.sin_family = AF_INET;
    m_servaddr.sin_addr.s_addr = INADDR_ANY;
    m_servaddr.sin_port = htons(PORT);

    if (bind(m_sockfd, (const struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Size of udphdr: " << sizeof(struct udphdr) << std::endl;
    std::cout << "Size of tcp_hdr: " << sizeof(struct tcp_hdr) << std::endl;

}

Reciever::~Reciever()
{
    std::cout << "Reciever::~Reciever()" << std::endl;
}

Interface* Reciever::recieve() {
    socklen_t addrlen = sizeof(m_cliaddr);
    char buffer[BUFFER_SIZE];
    Interface *inter;

    while (1)
    {
        int i = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&m_cliaddr, &addrlen);
        if(i > 0)
        {
            inter = new Interface(buffer);
            if(inter->tcpHeader()->from_serv == 0)
            {
                inter->setByte(i);
                std::cout << "recieved number - " << ntohs(inter->tcpHeader()->number) << std::endl;
                std::cout << "recieved ack number - " << ntohs(inter->tcpHeader()->ack_number) << std::endl;
                return inter;
            }
        }
        else
        {
            std::cout << "nooo\n";
        }
    }
    *inter = false;
    return inter;
}

std::array<char, BUFFER_SIZE> Reciever::create_packet(const struct tcp_hdr* tcp, const char* data, int data_size)
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

bool Reciever::connect() {
    std::cout << "Reciever::accept()" << std::endl;
    socklen_t len = sizeof(m_cliaddr);
    m_len = len;
    while (1) {
        // SYN
        auto interf = recieve();
        if (interf) 
        {
            if(interf->ipHeader()->daddr != inet_addr(m_addr.c_str())) { continue; }
            if(verify_checksum(interf->getPacket().data(), interf->getByte(), m_addr.c_str(), m_addr.c_str()))
            {
                if (interf->tcpHeader()->syn == 1 && interf->tcpHeader()->ack == 0) 
                {    
                    // std::cout << "Reciever::accept() - SYN" << std::endl;
                    std::cout << "test data - " << interf->data() <<std::endl;
                    m_number = htons(interf->tcpHeader()->number);

                    // SYN-ACK
                    auto tcp = new tcp_hdr;
                    // Setup TCP header for SYN-ACK response
                    char *data = "shalom";
                    auto data_len = strlen(data);
                    tcp->ack = 1;
                    tcp->ack_number = htons(ntohs(interf->tcpHeader()->number) + interf->getByte() + 1);
                    tcp->number = htons(m_number); // Initial sequence number
                    tcp->syn = 1;
                    tcp->from_serv = 1;
                    tcp->window_size = data_len;

                    std::cout << "sending number - " << ntohs(tcp->number) << std::endl;
                    std::cout << "sending ack number - " << ntohs(tcp->ack_number) << std::endl;

                    auto SYN_ACK_packet = create_packet(tcp, data, data_len);
                    int j = sendto(m_sockfd, std::next(SYN_ACK_packet.begin(), sizeof(pseudo_header)), sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_len, 0, (struct sockaddr *)&m_servaddr, len);
                    if (j < 0) 
                    {
                        perror("sendto failed");
                        std::cout << "sendto failed with error code: " << errno << std::endl;
                    } 
                    else 
                    {
                        //ACK
                        auto interfi = recieve();
                        if(!verify_checksum(interfi->getPacket().data(), interfi->getByte(), m_addr.c_str(), m_addr.c_str()))
                        {
                            std::cout << "!checksum ack" << std::endl; 
                            break;
                        }  
                        if (interfi) 
                        {
                            if (interfi->tcpHeader()->ack == 1 && interfi->tcpHeader()->syn == 0) 
                            {
                                m_number = ntohs(interfi->tcpHeader()->ack_number);
                                std::cout << "here - " << ntohs(interfi->tcpHeader()->ack_number) << std::endl;
                                std::cout << "Connection established " << ntohs(interfi->udpHeader()->check) <<  std::endl;
                                return true;
                            } 
                            else 
                            {
                                std::cout << "Connection not established" << std::endl;
                                continue;
                            }
                        }
                    }
                }
            }
        } else {
            std::cout << "else - -" << std::endl;
            return false;
        }
    }
    return false;
}

void Reciever::accept()
{
    std::cout << "Reciever::accept() " << std::endl;
    auto interf = recieve();
    if(verify_checksum(interf->getPacket().data(), interf->getByte(), m_addr.c_str(), m_addr.c_str())) 
    {
        std::cout << "Recieved from client - " <<  interf->data() << std::endl;

        auto tc = new tcp_hdr();
        tc->ack = 1;
        tc->from_serv = 1;

        std::cout << "test - " << ntohs(interf->tcpHeader()->number) << " n - " << interf->getByte() << std::endl;

        tc->ack_number = htons(ntohs(interf->tcpHeader()->number) + interf->getByte() + 1);

        auto packet = create_packet(tc, nullptr, 0);

        auto n = sendto(m_sockfd, std::next(packet.data(), sizeof(pseudo_header)), m_sizeheaders, 0, (struct sockaddr *)&m_cliaddr, m_len);
        if(n < 0)
        {
            std::cout << "ack was not sended - accept() " << std::endl;
        }
    }
    else
    {
        //smth
    }
}
                    //auto ack_packet = std::make_unique<unsigned char []>(1024);


// std::array<char, 1024> Reciever::create_packet(const struct tcp_hdr& tcp, const char* data, int data_size)
// {
//     std::cout << "Reciever::create_packet()" << std::endl;
//     std::array<char, 1024> packet;
//     packet.fill('\0');

//     struct udphdr *udph = (struct udphdr *)(packet.data());
//     udph->source = htons(m_port);
//     udph->dest = htons(m_port);
//     udph->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
//     udph->check = 0; 

//     struct tcp_hdr *tcph = (struct tcp_hdr *)(packet.data() + sizeof(struct udphdr));
//     *tcph = tcp;

//     memcpy(packet.data() + sizeof(struct udphdr) + sizeof(struct tcp_hdr), data, data_size);
//     udph->check = htons(calculate_checksum(packet.data(), sizeof(struct udphdr) + sizeof(tcp_hdr) + data_size));
//     return packet;
// }

// int Reciever::accept() {
//     std::cout << "Reciever::accept()" << std::endl;
//     char packet2[2048];
//     auto packet = std::make_unique<unsigned char [ ]>(1024);
//     socklen_t len = sizeof(m_cliaddr);
//     Interface *interf; 
//     while (1) {
//         // SYN
//         int n = recvfrom(m_sockfd, packet.get(), 1024, 0, (struct sockaddr *)&m_cliaddr, &len);
//         if (n > 0) {
//             interf = new Interface(packet.release());
//             if(interf->ipHeader().daddr != inet_addr(m_addr.c_str())) {
//                 continue;
//             }
//             std::cout << "Recieve n -  " << n << std::endl;
//             if (interf->tcpHeader().syn == 1 && interf->tcpHeader().ack == 0) {
//                 // SYN-ACK
//                 std::cout << "Reciever::accept() - SYN" << std::endl;
//                 tcp_hdr tcp;
//                 memset(&tcp, 0, sizeof(tcp_hdr));
                
//                 // Setup TCP header for SYN-ACK response
//                 tcp.ack = 1;
//                 tcp.ack_number = htonl(ntohl(interf->tcpHeader().number) + 1);
//                 tcp.number = htonl(1); // Initial sequence number
//                 tcp.syn = 1;
//                 tcp.from_serv = 1;
                
//                 char *data = "shalom";
//                 auto data_len = strlen(data);
//                 std::cout << "data_len: " << data_len << std::endl;

//                 auto SYN_ACK_packet = create_packet(tcp, data, data_len);
//                 int j = sendto(m_sockfd, SYN_ACK_packet.data(), sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_len, 0, (struct sockaddr *)&m_servaddr, len);
//                 if (j < 0) {
//                     perror("sendto failed");
//                     std::cout << "sendto failed with error code: " << errno << std::endl;
//                 } else {
//                     std::cout << "sendto success - " << n << std::endl;
//                     auto ack_packet = std::make_unique<unsigned char []>(1024);
//                     // int r = recvfrom(m_sockfd, ack_packet.get(), 1024, 0, (struct sockaddr *) &m_cliaddr, &len);
//                     auto interfi = recieve();
//                     if (interfi) {
//                         // interf = new Interface(ack_packet.release());
//                         if (interfi->tcpHeader().ack == 1 && interfi->tcpHeader().syn == 0) {
//                             std::cout << "Connection established" << std::endl;
//                             break;
//                         } else {
//                             std::cout << "Connection not established" << std::endl;
//                         }
//                     }
//                 }
//             }
//         } else {
//             std::cout << "else - -" << std::endl;
//         }
//     }
// }


                // char buffik[1024];
                // struct udphdr * uh = (struct udphdr *)buffik;

                // uh->source = htons(m_port);
                // uh->dest = htons(m_port);
                // uh->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
                // uh->check = 0; 

                // struct tcp_hdr* th = (struct tcp_hdr *)(buffik + sizeof(struct udphdr));
                // th->ack = 1;
                // th->syn = 1;
                // th->ack_number = htonl(ntohl(interf->tcpHeader().number) + 1);
                // th->number = htonl(1); // Initial sequence number
                
                // char* data = buffik + sizeof(struct iphdr) + sizeof(struct udphdr);

                // char buffik[1024];
                // struct udphdr * uh = (struct udphdr *)buffik;

                // uh->source = htons(m_port);
                // uh->dest = htons(m_port);
                // uh->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
                // uh->check = 0; 

                // struct tcp_hdr* th = (struct tcp_hdr *)(buffik + sizeof(struct udphdr));
                // th->ack = 1;
                // th->syn = 1;
                // th->ack_number = htonl(ntohl(interf->tcpHeader().number) + 1);
                // th->number = htonl(1); // Initial sequence number
                
                // char* data = buffik + sizeof(struct iphdr) + sizeof(struct udphdr);

                // const char* message = "Hello, World!";
                // int data_len = strlen(message);
                // strcpy(data, message);

                // uh->check =  htons(calculate_checksum(buffik, sizeof(struct udphdr) + sizeof(tcp_hdr) + data_len));
                // for(auto c : buffik)
                // {
                //     std::cout << c;
                // }
                // std::cout << std::endl;

                //int h = sendto(m_sockfd, buffik, sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_len, 0, (struct sockaddr *)&m_servaddr, len);


                    // char ack_packet[BUFFER_SIZE];

                                    // std::cout << "Reciever::accept() - SYN-ACK" << std::endl;
                // std::cout << "ack_packet - ";
                // for (auto c : SYN_ACK_packet) {
                //     std::cout << c;
                // }
                // std::cout << std::endl;
                    // char buffer[BUFFER_SIZE];
    // struct udphdr * ud = (struct udphdr *)(packet + sizeof(iphdr));
    // struct tcp_hdr * tc = (struct tcp_hdr *)(packet + sizeof(iphdr) + sizeof(udphdr));

    // unsigned short recieved = ud->check;

    // pseudo_header ps;

    // return true;
    // Interface intet((unsigned char *)packet);
    // char * buff = (char *)(packet + sizeof(struct iphdr));
        // auto dest_port = udh->dest;
    // char dest_port_str[6];
    // snprintf(dest_port_str, sizeof(dest_port_str), "%u", dest_port);
    // std::cout << "dest_port_str - " << dest_port_str << std::endl;
    // std::cout << "verify recived ip - " << ip_to_string(udh->dest) << std::endl;
    // std::cout << "verify recived ip interface - " << ip_to_string(intet.udpHeader().dest) << std::endl;