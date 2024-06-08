#include "Sender.hpp"
#include <cstring>

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

Sender::Sender(std::string_view addr, int port) : m_addr(addr), m_port(port)
{
    std::cout << "Sender::Sender()" << std::endl;
    if ((m_sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    m_servaddr.sin_family = AF_INET;
    m_servaddr.sin_addr.s_addr = INADDR_ANY;
    m_servaddr.sin_port = htons(m_port);

    if (bind(m_sockfd, (const struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
}

Sender::~Sender()
{
    std::cout << "Sender::~Sender()" << std::endl;
}

// std::array<char, 1024> Sender::Interface::fillIpHeader()
// {
//     return m_buffer;
// }

bool Sender::connect()
{
    //create packet
    //send packet
    //receive packet
    //send ack
    const char *message = "Hello, Server!";
    int message_len = strlen(message);
    struct iphdr *iph = (struct iphdr *)m_buffer;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr) + message_len);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = calculate_checksum(m_buffer, sizeof(struct iphdr));
    iph->saddr = inet_addr(m_addr.c_str());
    iph->daddr = m_servaddr.sin_addr.s_addr;

    struct udphdr *udph = (struct udphdr *) (m_buffer + sizeof(struct iphdr));
    udph->source = htons(12345);
    udph->dest = htons(m_port);
    udph->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
    udph->check = calculate_checksum(&m_buffer, sizeof(struct udphdr));

    tcp_hdr *tcp = (struct tcp_hdr *) (m_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
    tcp->number = htons(34);
    tcp->ack_number = htons(47);
    tcp->len = htons(sizeof(struct tcp_hdr));
    tcp->syn = htons(1);

    memcpy(m_buffer + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr), message, message_len);
    if (sendto(m_sockfd, m_buffer, ntohs(iph->tot_len), 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
        perror("sendto failed");
    } else {
        std::cout << "Message sent to server." << std::endl;
    }
    // tcp_hdr *tcp = (struct tcp_hdr *) (m_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
    // tcp->number = htons(1);
    // tcp->ack_number = htons(0);
    // tcp->len = sizeof(struct tcp_hdr);
    // tcp->syn = 1;
    // sendto(m_sockfd, m_buffer, htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr)), 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
}