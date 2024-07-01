#include "Reciever.hpp"

#include <cstring>
#include <memory>
#include <iostream>
#include <chrono>
#include <random>
#include <iterator>
#include <thread>
#include <queue>
#include <algorithm>

#define PORT 8080

Reciever::Reciever() : m_addr("127.0.0.1"), m_number(generate_isn()), m_sockfd(-1), m_port(8080), m_len(0), m_prevPackNumber(0),
    m_sizeheaders(sizeof(struct udphdr) + sizeof(struct tcp_hdr))
{
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
            inter = new Interface(buffer); // new...
            if(inter->tcpHeader()->from_serv == 0)
            {
                inter->setByte(i);
                *inter = true;
                return inter;
            }
        }
        else
        {
            continue;
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

bool Reciever::connect() { // change naming to listen or accept
    socklen_t len = sizeof(m_cliaddr);
    m_len = len;
    while (1) { // use true instead
        // SYN
        // remove nesting
        auto interf = recieve();
        if (!interf) return false;

        if(interf->ipHeader()->daddr != inet_addr(m_addr.c_str())) { continue; }
        if(!verify_checksum(interf->getPacket().data(), interf->getByte(), m_addr.c_str(), m_addr.c_str()))
            return false;

        if (interf->tcpHeader()->syn == 1 && interf->tcpHeader()->ack != 0)
            return false

        m_number = htons(interf->tcpHeader()->number);

        // move to create_packet function
        // SYN-ACK
        auto tcp = new tcp_hdr; // memore leak
        // Setup TCP header for SYN-ACK response
        char *data = "hi!";
        auto data_len = strlen(data); // static constexpr
        tcp->ack = 1;
        tcp->ack_number = htons(ntohs(interf->tcpHeader()->number) + 1);
        tcp->number = htons(m_number); // Initial sequence number
        tcp->syn = 1;
        tcp->from_serv = 1;
        tcp->window_size = data_len;

        m_prevPackNumber = ntohs(tcp->ack_number);
        std::cout << "sending number - " << ntohs(tcp->number) << std::endl;
        std::cout << "sending ack number - " << ntohs(tcp->ack_number) << std::endl;

        auto SYN_ACK_packet = create_packet(tcp, data, data_len);
        int j = sendto(m_sockfd, std::next(SYN_ACK_packet.begin(), sizeof(pseudo_header)), sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_len, 0, (struct sockaddr *)&m_servaddr, len);
        if (j < 0)
        {
            perror("sendto failed");
            return false;
        }
            //ACK
        auto interfi = recieve();
        if(!verify_checksum(interfi->getPacket().data(), interfi->getByte(), m_addr.c_str(), m_addr.c_str()))
        {
            std::cout << "!checksum ack" << std::endl;
            return false;
        }

        if (!interfi) return false;

        if (interfi->tcpHeader()->ack == 1 && interfi->tcpHeader()->syn != 0) continue;

        m_number = ntohs(interfi->tcpHeader()->ack_number);
        std::cout << "Connection established " <<  std::endl;
        return true;
    }
    return false;
}

void Reciever::accept() // WTF?
{
    std::vector<Interface *> window;
    std::vector<int> miss_pack;
    
    // decompose to functions
    while (true)
    {
        auto interf = recieve();
        printf("%.*s\n", ntohs(interf->tcpHeader()->window_size), interf->data());
        window.emplace_back(interf);
        
        if (ntohs(interf->tcpHeader()->count_packets) > 1) // why accept can be more than 1 packet? Resolved
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
            continue;
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
                printf("%.*s\n", ntohs(window[i]->tcpHeader()->window_size), window[i]->data());
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
            tc->from_serv = 1;
            tc->ack_number = htons(i);

            auto packet = create_packet(tc, nullptr, 0);

            auto n = sendto(m_sockfd, std::next(packet.data(), sizeof(pseudo_header)), m_sizeheaders, 0, (struct sockaddr *)&m_cliaddr, m_len);
            if (n < 0)
            {
                std::cout << "ack was not sent - accept() " << std::endl;
            }
        }

        window.clear();
        miss_pack.clear();
        ++m_prevPackNumber;
    }
}

bool Reciever::send(const char * packet, int number)
{
    std::cout << "Sender::send()" << std::endl;
    if(number == -1){number = m_number;}
    auto data_len = strlen(packet);
    tcp_hdr * tc = new tcp_hdr();
    tc->from_serv = 1;
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
            std::cout << "else " << std::endl; // WTF
        }

        if(interf){ std::cout << "resending ...\n"; send(packet); }
    }
    return false;
}

//sliced window implementation
bool Reciever::send(std::vector<char *> packets)
{
    int counter = 1;
    for(size_t i = 0; i < packets.size(); ++i)
    {
        auto len = strlen(packets[i]);
        auto tcp = std::make_shared<tcp_hdr>();
        tcp->number = htons(m_number + counter);
        tcp->from_serv = 1;
        tcp->window_size = htons(len);
        tcp->count_packets = htons(packets.size() - i-1);
        std::cout << "len - " << ntohs(tcp->count_packets) << std::endl;

        std::cout << "sending packet no - " << m_number + counter << std::endl;
        auto pack = create_packet(tcp.get(), packets[i], len);
        sendto(m_sockfd, std::next(pack.begin(), sizeof(pseudo_header)), m_sizeheaders + len ,0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
        ++counter;
    }

    std::cout << "m_number - " <<  m_number << std::endl;
    std::cout << "counter - " <<  counter << std::endl;
    int expected = m_number + counter;
    std::cout << "expected - " <<  expected << std::endl;
    while(1)
    {
        auto pack = recieve();
        int number = htons(pack->tcpHeader()->ack_number);
        std::cout << "expected packet number - " << number  <<std::endl;
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