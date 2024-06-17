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

Reciever::Reciever() : m_addr("127.0.0.1"), m_number(2), m_sockfd(-1), m_port(8080), m_len(0), m_sack(false), m_prevPackNumber(0),
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
                std::cout << "ns - " << ntohs(inter->tcpHeader()->ns) << std::endl;
                if(ntohs(inter->tcpHeader()->ns) == 1)
                {
                    m_sack = true; 
                    std::cout << "if ... ns \n";
                    // auto tcp = new tcp_hdr();
                    // tcp->ns = htons(1);
                }
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
            else
            {
                std::cout << "!checksum" << std::endl;
            }
        } 
        else 
        {
            std::cout << "else - -" << std::endl;
            return false;
        }
    }
    return false;
}

void Reciever::accept()
{
    std::cout << "Reciever::accept() " << std::endl;
    std::vector<Interface *> window;
    std::vector<int> miss_pack;
    while(1)
    {
        //1
        auto interf = recieve();
        window.emplace_back(interf);
        std::cout << "len - " << ntohs(interf->tcpHeader()->count_packets) << std::endl;
        std::cout << "data - " << interf->data() << std::endl;
        if(ntohs(interf->tcpHeader()->count_packets) > 1)
        {   
            for(;;){
                auto intr = recieve();
                if(ntohs(intr->tcpHeader()->number) > ntohs(interf->tcpHeader()->count_packets))
                {
                    window.emplace_back(intr);
                }
                if(ntohs(intr->tcpHeader()->count_packets)==0){break;}
            }
        }
        std::cout << "prev - " << m_prevPackNumber << std::endl;
        //2

        try
        {
            if(ntohs(window[0]->tcpHeader()->number) - m_prevPackNumber != 1)
            {
                miss_pack.emplace_back(ntohs(window[0]->tcpHeader()->number));
            }
        }
        catch(std::exception &e)
        {
            std::cout << "exeption - " << e.what() << std::endl;
        }
        
        std::cout << "uga buga " << std::endl;

        for(auto i : window)
        {
            std::cout << "number - " << ntohs(i->tcpHeader()->number) << std::endl;
        }

        try
        {
            for(auto i = 1; i < window.size();++i)
            {   
                std::cout << "ntohs(window[i]->tcpHeader()->number)" << ntohs(window[i]->tcpHeader()->number) << std::endl;
                std::cout << "ntohs(window[i-1]->tcpHeader()->number)" << ntohs(window[i-1]->tcpHeader()->number) << std::endl;
                if(ntohs(window[i]->tcpHeader()->number) - ntohs(window[i-1]->tcpHeader()->number) > 1)
                {
                    for(int j = ntohs(window[i-1]->tcpHeader()->number); i < ntohs(window[i]->tcpHeader()->number); ++i)
                    {
                        miss_pack.emplace_back(i);
                    }
                }
                if(verify_checksum(window[i]->getPacket().data(), window[i]->getByte(), m_addr.c_str(), m_addr.c_str())) 
                {
                    std::cout << "Recieved from client - " <<  window[i]->data() << std::endl;
                }
                else
                {
                    miss_pack.emplace_back(i);
                }
            } 
        }
        catch(std::exception &e)
        {
            std::cout << "exeption - " << e.what() << std::endl;
        }
          

        miss_pack.emplace_back(ntohs(window.back()->tcpHeader()->number) + 1);
        auto last = std::unique(miss_pack.begin(), miss_pack.end());
        miss_pack.erase(last, miss_pack.end());

        std::cout << "contains vector" << std::endl;
        for(auto i : miss_pack)
        {
            std::cout << i << " ";
        }
        std::cout << std::endl;
        //3
        for(auto i : miss_pack)
        {
            auto tc = new tcp_hdr();
            tc->ack = 1;
            tc->from_serv = 1;

            // std::cout << "test - " << ntohs(pack->tcpHeader()->number) << " n - " << pack->getByte() << std::endl;
            tc->ack_number = htons(i);

            auto packet = create_packet(tc, nullptr, 0);

            auto n = sendto(m_sockfd, std::next(packet.data(), sizeof(pseudo_header)), m_sizeheaders, 0, (struct sockaddr *)&m_cliaddr, m_len);
            if(n < 0)
            {
                std::cout << "ack was not sended - accept() " << std::endl;
            }
        }
        window.clear();
        miss_pack.clear();
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