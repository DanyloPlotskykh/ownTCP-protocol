#include "Sender.hpp"
#include <cstring>
#include <chrono>
#include <random>
#include <memory>
#include <algorithm>

#define PORT 8080
#define SERVER_IP "127.0.0.1"
Sender::Sender(std::string_view addr, int port) : m_addr(addr), m_port(port), m_prevPackNumber(0),
        m_sizeheaders(sizeof(struct udphdr)+ sizeof(struct tcp_hdr)), m_number(generate_isn())

{
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

    for(int i = 0; i <= 2; ++i)
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
    } 
    char buffer[1024];
    socklen_t addrlen = sizeof(m_servaddr);
    auto interface = recieve();
    if (interface) {
        std::cout << "Server reply received." << std::endl;
        if (interface->tcpHeader()->syn == 1 && interface->tcpHeader()->ack == 1) {
            // Send ACK to complete three-way handshake
            m_prevPackNumber = ntohs(interface->tcpHeader()->number);
            m_number = ntohs(interface->tcpHeader()->ack_number);
            tcp_hdr *ack_tcp = new tcp_hdr();
            ack_tcp->ack = 1;
            ack_tcp->number = htons(m_number);
            ack_tcp->ack_number = htons(ntohs(interface->tcpHeader()->number) + 1);
            ack_tcp->syn = 0;
            ack_tcp->from_serv = 0;
            ack_tcp->window_size = htons(0);

            std::cout << "sending number - " << ntohs(ack_tcp->number) << std::endl;
            std::cout << "sending ack number - " << ntohs(ack_tcp->ack_number) << " len -  " << interface->getByte() <<  std::endl;

            auto ack_packet = create_packet(ack_tcp, nullptr, 0);
            if (sendto(m_sockfd, std::next(ack_packet.begin(), sizeof(struct pseudo_header)), m_sizeheaders, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr)) < 0) {
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

//no sack implementation
bool Sender::send(const char * packet, int number)
{
    if(number == -1){number = m_number;}
    auto data_len = strlen(packet);
    tcp_hdr * tc = new tcp_hdr();
    tc->from_serv = 0;
    tc->ack = 0;
    tc->number = htons(++number);
    tc->SACK = 0;
    tc->window_size = htons(data_len);
    auto pack = create_packet(tc, std::move(packet), data_len);

    int n = sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + data_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
    if(n > 0)
    {
        std::cout << "send Success " << std::endl;
        auto interf = recieve();

        std::cout << "recieved ack send() - " << ntohs(interf->tcpHeader()->ack_number) << " number - " << number << std::endl; 

        if(ntohs(interf->tcpHeader()->ack_number) - number == 1)
        {
            ++m_number;
            std::cout << "packet has been ack " << std::endl;
            return true;
        }
        else
        {
            std::cout << "else " << std::endl;
        }

        if(interf){ std::cout << "resending ...\n"; send(packet); }
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
        tcp->from_serv = 0;
        tcp->window_size = htons(len);
        tcp->count_packets = htons(packets.size() - i-1);
        auto pack = create_packet(tcp.get(), packets[i], len);
        sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + len ,0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
        ++counter;
    }
    int expected = m_number + counter;
    while(1)
    {
        auto pack = recieve();
        int number = htons(pack->tcpHeader()->ack_number);
        if(number == 0){continue;}
        if(number >= expected)
        {
            m_number +=counter;
            return true;
        }
        else
        {
            send(packets[number-m_number], number);
        }
    }
    return false;
}

// void Sender::accept1()
// {
//     auto interf = recieve();
//     if(!interf)
//     {
//         std::cout << "something wrong ... " << std::endl; 
//     }
//     else
//     {
//         std::cout << "data recieved - " << interf->data() << std::endl;
//     }
// }

void Sender::accept()
{
    std::vector<Interface *> window;
    std::vector<int> miss_pack;
        auto interf = recieve();
        if(!interf)
        {
            return;
        }
        window.emplace_back(interf);
        
        if (ntohs(interf->tcpHeader()->count_packets) > 1)
        {   
            while (true)
            {
                auto intr = recieve();
                if (ntohs(intr->tcpHeader()->number) > ntohs(interf->tcpHeader()->count_packets))
                {
                    window.emplace_back(intr);
                }
                if (ntohs(intr->tcpHeader()->count_packets) == 0)
                {
                    break;
                }
            }
        }

        if (window.empty())
        {
            return;
        }

        if (ntohs(window[0]->tcpHeader()->number) - m_prevPackNumber != 1)
        {
            miss_pack.emplace_back(ntohs(window[0]->tcpHeader()->number));
        }

        for (size_t i = 1; i < window.size(); ++i)
        {   
            if (ntohs(window[i]->tcpHeader()->number) - ntohs(window[i - 1]->tcpHeader()->number) > 1)
            {
                for (int j = ntohs(window[i - 1]->tcpHeader()->number) + 1; j < ntohs(window[i]->tcpHeader()->number); ++j)
                {
                    miss_pack.emplace_back(j);
                }
            }

            if (verify_checksum(window[i]->getPacket().data(), window[i]->getByte(), m_addr.c_str(), m_addr.c_str())) 
            {
                std::cout << "Received from client - " <<  window[i]->data() << std::endl;
            }
            else
            {
                miss_pack.emplace_back(ntohs(window[i]->tcpHeader()->number));
            }
        }

        miss_pack.emplace_back(ntohs(window.back()->tcpHeader()->number) + 1);
        auto last = std::unique(miss_pack.begin(), miss_pack.end());
        miss_pack.erase(last, miss_pack.end());

        for (auto i : miss_pack)
        {
            auto tc = new tcp_hdr();
            tc->ack = 1;
            tc->from_serv = 0;
            tc->ack_number = htons(i);

            auto packet = create_packet(tc, nullptr, 0);

            auto n = sendto(m_sockfd, std::next(packet.data(), sizeof(pseudo_header)), m_sizeheaders, 0, (struct sockaddr *)&m_servaddr, m_len);
            if (n < 0)
            {
                std::cout << "ack was not sent - accept() " << std::endl;
            }
        }

        window.clear();
        miss_pack.clear();
        ++m_prevPackNumber;
}