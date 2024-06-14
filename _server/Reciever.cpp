#include "Reciever.hpp"

#include <cstring>
#include <memory>
#include <iostream>
#include <chrono>
#include <random>
#include <iterator>
#include <thread>

#define PORT 8080

tcp_hdr& tcp_hdr::operator=(const tcp_hdr& other)
{
    if (this == &other) {
        return *this;
    }
    std::cout << "tcp_hdr::operator=()" << std::endl;
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
    
    struct udphdr * ud = (struct udphdr *)(packet + sizeof(iphdr));
    unsigned short recieved = ud->check;
    std::cout << "verify recived checksum - " << htons(recieved) << std::endl;
    struct tcp_hdr *tc = (struct tcp_hdr *)(packet + sizeof(iphdr) + sizeof(udphdr));   
    std::cout << "verify received len - " << htons(ud->len) << std::endl;

    pseudo_header psh;
    psh.source_address = inet_addr(src_ip);
    psh.dest_address = inet_addr(dest_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(packet_len);

    int psize = sizeof(udphdr) + sizeof(pseudo_header) + sizeof(tcp_hdr) + packet_len;
    char * buff = new char[psize];

    memcpy(buff, ud, sizeof(udphdr));
    memcpy(buff + sizeof(udphdr), &psh, sizeof(pseudo_header));
    memcpy(buff + sizeof(udphdr) + sizeof(pseudo_header), tc, sizeof(tcp_hdr));
    memcpy(buff + sizeof(udphdr) + sizeof(pseudo_header) + sizeof(tcp_hdr), packet, packet_len);

    auto lenn = strlen(buff);

    unsigned short calculated_checksus = calculate_checksum(buff, lenn);
    std::cout << "verify calculated checksum - " << calculated_checksus << std::endl;

    return (calculated_checksus == htons(recieved));
}

static uint32_t generate_isn() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

    std::mt19937_64 rng(nanos);
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

    return dist(rng);
}

Interface::Interface(const unsigned char* packet) : trueOrFalseCond(false), m_bytes(0)
{
    std::cout << "Interface::Interface()" << std::endl;
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

Reciever::Reciever() : m_addr("127.0.0.1"), ack(0), m_number(0), m_sockfd(-1), m_port(8080), m_len(0),
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
            inter = new Interface((const unsigned char *)buffer);
            if(inter->tcpHeader()->from_serv == 0)
            {
                std::cout << "cool\n";
                inter->setByte(i);
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

std::array<char, BUFFER_SIZE> Reciever::create_packet(const struct tcp_hdr& tcp, const char* data, int data_size)
{
    std::cout << "Reciever::create_packet()" << std::endl;
    std::array<char, BUFFER_SIZE> packet;
    struct udphdr *udph = (struct udphdr *)(packet.data());
    udph->source = htons(m_port);
    udph->dest = htons(m_port);
    udph->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
    udph->check = 0; 
    struct tcp_hdr *tcph = (struct tcp_hdr *)(packet.data() + sizeof(struct udphdr));
    *tcph = tcp;
    tcph->len = calculate_checksum(packet.data(), sizeof(struct tcp_hdr));
    pseudo_header psh;
    psh.source_address = inet_addr(m_addr.c_str());
    psh.dest_address = inet_addr(m_addr.c_str());
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_size);

    int psize = sizeof(udphdr) + sizeof(pseudo_header) + sizeof(tcp_hdr) + data_size;

    char * buff = new char[psize];

    memcpy(buff, udph, sizeof(udphdr));
    memcpy(buff + sizeof(udphdr), &psh, sizeof(pseudo_header));
    memcpy(buff + sizeof(udphdr) + sizeof(pseudo_header), tcph, sizeof(tcp_hdr));
    memcpy(buff + sizeof(udphdr) + sizeof(pseudo_header) + sizeof(tcp_hdr), data, data_size);

    int lenn = strlen(buff);

    memcpy(packet.data() + sizeof(struct udphdr) + sizeof(tcp_hdr), data, data_size);
    udph->check = htons(calculate_checksum(buff, lenn)); 
    std::cout << "calc - " << htons(udph->check) << std::endl;
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
                    std::cout << "Reciever::accept() - SYN" << std::endl;
                    std::cout << "test data - " << interf->data() <<std::endl;
                    m_number = htons(interf->tcpHeader()->number);

                    // SYN-ACK
                    tcp_hdr tcp;
                    memset(&tcp, 0, sizeof(tcp_hdr));
                    
                    // Setup TCP header for SYN-ACK response
                    tcp.ack = 1;
                    tcp.ack_number = htonl(ntohl(interf->tcpHeader()->number) + 1);
                    tcp.number = generate_isn(); // Initial sequence number
                    tcp.syn = 1;
                    tcp.from_serv = 1;
                    
                    char *data = "shalom";
                    auto data_len = strlen(data);
                    std::cout << "data_len: " << data_len << std::endl;

                    auto SYN_ACK_packet = create_packet(tcp, data, data_len);
                    int j = sendto(m_sockfd, SYN_ACK_packet.data(), sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_len, 0, (struct sockaddr *)&m_servaddr, len);
                    if (j < 0) 
                    {
                        perror("sendto failed");
                        std::cout << "sendto failed with error code: " << errno << std::endl;
                    } 
                    else 
                    {
                        std::cout << "sendto success - " << j << std::endl;
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
                                std::cout << "Connection established" << std::endl;
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
    // if(!ifConnected)
    // {
    //     std::cout << "server has not connected to any client yet" << std::endl;
    //     return;
    // }
    auto interf = recieve();
    if(verify_checksum(interf->getPacket().data(), interf->getByte(), m_addr.c_str(), m_addr.c_str())) 
    {
        std::cout << "Recieved from client - " <<  interf->data() << std::endl;

        tcp_hdr tc;
        tc.ack = 1;
        tc.syn = 0;
        tc.from_serv = 1;
        tc.ack_number = htons((interf->tcpHeader()->ack_number) + 1);
        tc.number = htons((interf->tcpHeader()->number) + 1);

        auto packet = create_packet(tc, nullptr, 0);

        auto n = sendto(m_sockfd, packet.data(), m_sizeheaders,0 ,(struct sockaddr *)&m_cliaddr, m_len);
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