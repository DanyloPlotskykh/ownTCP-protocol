#include "Reciever.hpp"
#include <iostream>
#include <cstring>

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
    this->SACK = other.SACK;
    return *this;
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

Interface::Interface(const char* packet)
{
    std::cout << "Interface::Interface()" << std::endl;
    memcpy(&p, packet, sizeof(pars));
}

Interface::~Interface()
{
    std::cout << "Interface::~Interface()" << std::endl;
}

iphdr Interface::ipHeader() const
{
    return p.ip;
}

udphdr Interface::udpHeader() const
{
    return p.udp;
}
tcp_hdr Interface::tcpHeader() const
{
    return p.tcp;
}

char * Interface::data() const
{

}

Reciever::Reciever() : ack(0), byte(0)
{
    std::cout << "Reciever::Reciever()" << std::endl;
    if ((m_sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
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
}

Reciever::~Reciever()
{
    std::cout << "Reciever::~Reciever()" << std::endl;
}

// std::array<char, 1024> Reciever::create_packet(const struct tcp_hdr& tcp, const char* data, int data_size)
// {
//     std::array<char, 1024> packet;
//     struct iphdr *iph = (struct iphdr *)packet.data();
//     iph->ihl = 5;
//     iph->version = 4;
//     iph->tos = 0;
//     iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_size);
//     iph->id = htonl(54321);
//     iph->frag_off = 0;
//     iph->ttl = 255;
//     iph->protocol = IPPROTO_UDP;
//     iph->check = calculate_checksum(packet.data(), sizeof(struct iphdr));
//     iph->saddr = inet_addr(m_addr.c_str());
//     iph->daddr = m_servaddr.sin_addr.s_addr;

//     struct udphdr *udph = (struct udphdr *)(packet.data() + sizeof(struct iphdr));
//     udph->source = htons(12345);
//     udph->dest = htons(m_port);
//     udph->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
//     udph->check = htons(calculate_checksum(&packet.data(), sizeof(struct udphdr)));

//     struct tcp_hdr *tcph = (struct tcp_hdr *)(packet.data() + sizeof(struct iphdr) + sizeof(struct udphdr));
//     *tcph = tcp;
//     memcpy(packet.data() + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr), data, data_size);
//     return packet;
// }

int Reciever::accept()
{
    std::cout << "Reciever::accept()" << std::endl;
    char packet[BUFFER_SIZE];
    socklen_t len = sizeof(m_cliaddr);
    Interface *interf; 
    while(1)
    {
        int n = recvfrom(m_sockfd, packet, sizeof(packet), 0, (struct sockaddr *) &m_cliaddr, &len);
        if(n > 0)
        {
            interf = new Interface(packet);
            if(interf->tcpHeader().syn == 1)
            {
                //SYN-ACK
                std::cout << "Reciever::accept() - SYN" << std::endl;
                //sendto(m_sockfd)
            }
        }
        else
        {
            std::cout << "else - - " << std::endl;
        }
    }
}







            // std::cout << "Reciever::accept() - n - " << n << std::endl;
            // std::cout << "Reciever::accept() - syn =  " << interf->tcpHeader().syn << std::endl;
            // std::cout << "Reciever::accept() - ack =  " << interf->tcpHeader().ack_number << std::endl;
            // std::cout << "Reciever::accept() - number =  " << ntohl(interf->tcpHeader().number) << std::endl;
            // std::cout << "Reciever::accept() - syn =  " << interf->retur().tcp.syn << std::endl;
            // std::cout << "Reciever::accept() - ack =  " << interf->retur().tcp.ack_number << std::endl;
            // std::cout << "Reciever::accept() - number =  " << ntohs(interf->retur().tcp.number) << std::endl;