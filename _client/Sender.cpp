#include "Sender.hpp"
#include <cstring>
#include <chrono>
#include <random>
#include <memory>

#define PORT 8080
#define SERVER_IP "127.0.0.1"
Sender::Sender(std::string_view addr, int port) : m_addr(addr), m_port(port),
        m_sizeheaders(sizeof(struct udphdr)+ sizeof(struct tcp_hdr)), m_number(1)

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
            inter = new Interface(buffer);
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
            ack_tcp->ack_number = htons(ntohs(interface->tcpHeader()->number) + 1);
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
    tc->number = htons(++m_number);
    tc->SACK = 0;
    tc->window_size = htons(data_len);
    auto pack = create_packet(tc, std::move(packet), data_len);

    int n = sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + data_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
    if(n > 0)
    {
        std::cout << "send Success " << std::endl;
        auto interf = recieve();

        std::cout << "recieved ack send() - " << ntohs(interf->tcpHeader()->ack_number) << " m_number - " << m_number << std::endl; 

        if(interf->tcpHeader()->ack == 1 && ntohs(interf->tcpHeader()->ack_number) - m_number == 1)
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

//sliced window implementation
bool Sender::send(std::vector<char *> packets)
{
    int counter = 1;
    for(size_t i = 0; i < packets.size(); ++i)
    {
        auto len = strlen(packets[i]);
        auto tcp = std::make_shared<tcp_hdr>();
        tcp->number = htons(m_number + counter);
        tcp->SACK = 1;
        tcp->from_serv = 0;
        tcp->window_size = htons(len);
        tcp->count_packets = htons(packets.size() - i-1);
        std::cout << "len - " << ntohs(tcp->count_packets) << std::endl;

        std::cout << "sending packet no - " << m_number + counter << std::endl;
        auto pack = create_packet(tcp.get(), packets[i], len);
        sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + len ,0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
        ++counter;
    }
}