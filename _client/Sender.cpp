#include "Sender.hpp"
#include <cstring>

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

Interface::Interface(const char* packet)
{
    std::cout << "Interface::Interface()" << std::endl;
    memcpy(&p, packet, sizeof(pars));
}

iphdr Interface::ipHeader() const
{
    return p.ip;
}

Interface::~Interface()
{
    std::cout << "Interface::~Interface()" << std::endl;
}

udphdr Interface::udpHeader() const
{
    return p.udp;
}

tcp_hdr Interface::tcpHeader() const 
{
    return p.tcp;
}

Sender::Sender(std::string_view addr, int port) : m_addr(addr), m_port(port), 
        m_sizeheaders(sizeof(struct iphdr))
{
    std::cout << "Sender::Sender()" << std::endl;
    if ((m_sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    m_servaddr.sin_family = AF_INET;
    m_servaddr.sin_addr.s_addr = inet_addr(addr.data()); // Привязываем к конкретному IP-адресу клиента
    m_servaddr.sin_port = htons(m_port);

    if (bind(m_sockfd, (const struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
}

std::array<char, 1024> Sender::create_packet(const struct tcp_hdr& tcp, const char* data, int data_size)
{
    std::array<char, 1024> packet;
    struct iphdr *iph = (struct iphdr *)packet.data();
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcp_hdr) + data_size);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = calculate_checksum(packet.data(), sizeof(struct iphdr));
    iph->saddr = inet_addr(m_addr.c_str());
    iph->daddr = m_servaddr.sin_addr.s_addr;

    // struct udphdr *udph = (struct udphdr *)(packet.data() + sizeof(struct iphdr));
    // udph->source = htons(m_port);
    // udph->dest = htons(m_port);
    // udph->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr));
    // udph->check = htons(calculate_checksum(packet.data(), sizeof(struct udphdr))); // Необязательно для отправки пакетов с RAW сокетом
    // struct tcp_hdr *tcph = (struct tcp_hdr *)(packet.data() + sizeof(struct iphdr));
    // *tcph = tcp;
    // tcph->len = calculate_checksum(packet.data(), sizeof(struct tcp_hdr)); // Неправильное использование функции
    // std::cout << "calc - " << tcph->len << std::endl;
    memcpy(packet.data() + sizeof(struct iphdr), data, data_size);
    return packet;
}

bool Sender::connect()
{
    const char *message = "Hello, Server!";
    int message_len = strlen(message);
    tcp_hdr tcp;
    tcp.number = htons(34);
    tcp.ack_number = htons(47);
    tcp.syn = 1;
    tcp.ack = 0;

    auto packet = create_packet(tcp, message, message_len);
    if (sendto(m_sockfd, packet.data(), m_sizeheaders + message_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
        perror("sendto failed");
    } else {
        std::cout << "Message sent to server." << std::endl;
    }

    char buffer[1024];
    socklen_t addrlen = sizeof(m_servaddr);
    int n = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&m_servaddr, &addrlen);
    if (n > 0) {
        std::cout << "Server reply received." << std::endl;
        Interface reply(buffer);
        if (reply.tcpHeader().syn == 1 && reply.tcpHeader().ack == 1) {
            std::cout << "Received SYN-ACK from server." << std::endl;
            std::cout << "Server reply: " << buffer << std::endl;

            // Send ACK to complete three-way handshake
            tcp_hdr ack_tcp;
            ack_tcp.ack = 1;
            ack_tcp.number = reply.tcpHeader().ack_number;
            ack_tcp.ack_number = htonl(ntohl(reply.tcpHeader().number) + 1);
            auto ack_packet = create_packet(ack_tcp, nullptr, 0);
            if (sendto(m_sockfd, ack_packet.data(), m_sizeheaders, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
                perror("sendto failed");
            } else {
                std::cout << "ACK sent to server." << std::endl;
            }
        }
    } else {
        perror("recvfrom failed");
        std::cout << "recvfrom failed with error code: " << errno << std::endl;
    }
    return true;
}


    // tcp_hdr *tcp = (struct tcp_hdr *) (m_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
    // tcp->number = htons(1);
    // tcp->ack_number = htons(0);
    // tcp->len = sizeof(struct tcp_hdr);
    // tcp->syn = 1;
    // sendto(m_sockfd, m_buffer, htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr)), 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));