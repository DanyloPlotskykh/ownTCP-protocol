#include "Sender.hpp"
#include <cstring>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <condition_variable>


#define PORT 8080
#define SERVER_IP "127.0.0.1"

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

tcp_hdr::tcp_hdr() {
    std::cout << "tcp_hdr::tcp_hdr()" << std::endl;
    number = 0;
    ack_number = 0;
    len = 0;
    reserved = 0;
    ns = 0;
    cwr = 0;
    ece = 0;
    fin = 0;
    syn = 0;
    rst = 0;
    psh = 0;
    ack = 0;
    urg = 0;
    window_size = 0;
    from_serv = 0;
    SACK = 0;
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

Sender::Sender(std::string_view addr, int port) : m_addr(addr), m_port(port), m_ackNumber(0),
        m_sizeheaders(sizeof(struct udphdr)+ sizeof(struct tcp_hdr)), stop_timer(false), isStoped(false),
        m_number(generate_isn())

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
}

std::array<char, 1024> Sender::create_packet(const struct tcp_hdr& tcp, const char* data, int data_size)
{
    std::array<char, 1024> packet;
    packet.fill('\0');
    std::cout << "test str lenght data - " << data_size << std::endl;
    struct udphdr *udph = (struct udphdr *)(packet.data());
    udph->source = htons(m_port);
    udph->dest = htons(m_port);
    udph->len = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_size);
    udph->check = 0; 
    struct tcp_hdr *tcph = (struct tcp_hdr *)(packet.data() + sizeof(struct udphdr));
    *tcph = tcp;
    tcph->len = calculate_checksum(packet.data(), sizeof(struct tcp_hdr));
    pseudo_header psh;
    psh.source_address = inet_addr("127.0.0.1");
    psh.dest_address = inet_addr("127.0.0.1");
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_size);

    int psize = sizeof(struct udphdr) + sizeof(struct pseudo_header) + sizeof(struct tcp_hdr) + data_size;

    char * buff = new char[psize];
    memset(buff, 0, psize);

    memcpy(buff, &psh, sizeof(pseudo_header));
    memcpy(buff + sizeof(pseudo_header), udph, sizeof(udphdr));
    memcpy(buff + sizeof(pseudo_header) + sizeof(udphdr), tcph, sizeof(tcp_hdr));
    memcpy(buff + sizeof(pseudo_header) + sizeof(udphdr) + sizeof(tcp_hdr), data, data_size);

    int lenn = strlen(buff);

    memcpy(packet.data() + sizeof(struct udphdr) + sizeof(tcp_hdr), data, data_size);
    udph->check = htons(calculate_checksum(buff, psize)); 
    std::cout << "checksum - " << ntohs(udph->check) << std::endl;
    return packet;
}

Interface* Sender::recieve() {
    socklen_t addrlen = sizeof(m_servaddr);
    char buffer[1024];
    Interface *inter;

    while (1)
    {
        int i = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&m_servaddr, &addrlen);
        if(i > 0)
        {
            inter = new Interface((unsigned char *)buffer);
            if(inter->tcpHeader()->from_serv == 1)
            {
                std::cout << "cool\n";
                return inter;
            }
        }
        else
        {
            if(isStoped){break;}
            std::cout << "nooo\n";
        }
    }
    *inter = false;
    return inter;
}

bool Sender::connect()
{
    const char *message = "Hello, Server!";
    int message_len = strlen(message);
    tcp_hdr tcp;
    tcp.number = htons(m_number);
    tcp.ack_number = 0;
    tcp.syn = 1;
    tcp.ack = 0;
    tcp.from_serv = 0;

    auto packet = create_packet(tcp, message, message_len);
    int d;
    if ((d = sendto(m_sockfd, packet.data(), m_sizeheaders + message_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr))) < 0) {
        perror("sendto failed");
    } else {
        std::cout << "Message sent to server. "  << d << "  " << message_len << std::endl;
    }
    
    char buffer[1024];
    socklen_t addrlen = sizeof(m_servaddr);
    auto interface = recieve();
    if (interface) {
        std::cout << "Server reply received." << std::endl;
        std::cout << "tcp-syn, ack - " << (interface->tcpHeader()->syn) << " " << (interface->tcpHeader()->ack) << std::endl;
        if (interface->tcpHeader()->syn == 1 && interface->tcpHeader()->ack == 1) {
            std::cout << "Received SYN-ACK from server." << std::endl;
            // Send ACK to complete three-way handshake
            tcp_hdr ack_tcp;
            ack_tcp.ack = 1;
            ack_tcp.number = 0;
            ack_tcp.ack_number = htonl(ntohl(interface->tcpHeader()->number) + 1);
            ack_tcp.syn = 0;
            ack_tcp.from_serv = 0;

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

void timer(std::atomic<bool>& stop_timer, std::condition_variable& cv, std::mutex& cv_m, std::atomic<bool>& isStoped)
{
    std::unique_lock<std::mutex> lk(cv_m);
    while (true) {
        if (cv.wait_for(lk, std::chrono::seconds(15), [&]{ return stop_timer.load(); })) {
            std::cout << "Timer stopped!\n";
            break;
        } else {
            isStoped = true;
            break;
        }
    }
}

//no sack implementation
bool Sender::send(const char * packet)
{
    // for timer
    std::condition_variable cv;
    std::mutex cv_m;
    std::thread timerThread([this, &cv, &cv_m]{timer(this->stop_timer, cv, cv_m, this->isStoped);});
    std::cout << "Sender::send()" << std::endl;
    auto data_len = strlen(packet);
    tcp_hdr tc;
    tc.from_serv = 0;
    tc.ack = 0;
    tc.number = htons(m_number);
    tc.ack_number = htons(m_ackNumber);
    tc.SACK = 0;
    auto pack = create_packet(tc, std::move(packet), sizeof(packet));

    int n = sendto(m_sockfd, pack.data(), m_sizeheaders + data_len, 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));
    if(n > 0)
    {
        std::cout << "send Success " << std::endl;
        auto interf = recieve();

        if(interf->tcpHeader()->ack == 1 && ntohs(interf->tcpHeader()->ack_number) - m_ackNumber == 1)
        {
            std::cout << "tryin to stop timer " << std::endl;
            stop_timer = true;
            cv.notify_one();
            std::cout << "packet has been ack " << std::endl;
        }
        else
        {
            std::cout << "else " << std::endl;
        }

        if(!stop_timer){ std::cout << "resending ...\n"; send(packet); }
    }
    timerThread.join();
    (!stop_timer) ? send(packet) : stop_timer = false;
}

    // tcp_hdr *tcp = (struct tcp_hdr *) (m_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
    // tcp->number = htons(1);
    // tcp->ack_number = htons(0);
    // tcp->len = sizeof(struct tcp_hdr);
    // tcp->syn = 1;
    // sendto(m_sockfd, m_buffer, htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr)), 0, (struct sockaddr *)&m_servaddr, sizeof(m_servaddr));

    // struct iphdr *iph = (struct iphdr *)packet.data();
    // iph->ihl = 5;
    // iph->version = 4;
    // iph->tos = 0;
    // iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr) + data_size);
    // iph->id = htonl(54321);
    // iph->frag_off = 0;
    // iph->ttl = 255;
    // iph->protocol = IPPROTO_UDP;
    // iph->check = calculate_checksum(packet.data(), sizeof(struct iphdr));
    // iph->saddr = inet_addr(m_addr.c_str());
    // iph->daddr = m_servaddr.sin_addr.s_addr;

        // int n;
    // while (1)
    // {
    //     int n = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&m_servaddr, &addrlen);
    //     if(n > 0)
    //     {
    //         Interface inter(buffer);
    //         if(inter.tcpHeader().from_serv == 1 && inter.ipHeader().daddr == inet_addr("127.0.0.1"))
    //         {
    //             std::cout << "YES, YES, YES" << std::endl;
    //         }
    //         else
    //         {
    //             continue;
    //         }
    //     }
    // }

            // std::cout << "buffer 1 - "<< std::endl;
        // std::cout << std::endl;
        // for(auto c : buffer)
        // {
        //     std::cout << c;
        // }
        // std::cout << std::endl;
        // std::cout << "buffer 2 - "<< std::endl;
        // std::cout << std::endl;
        // for(auto c : buffer2)
        // {
        //     std::cout << c;
        // }
        // std::cout << std::endl;
        // Interface reply(buffer);
        // Interface s(buffer2);
        // std::cout << "n reply(in bytes)" << n << std::endl;
        // std::cout << " 2222222  tcp-syn, ack - " << (interface.tcpHeader().syn) << " " << (interface.tcpHeader().ack) << std::endl;

            // auto reply = recieve();
    // int a = recvfrom(m_sockfd, buffer2, sizeof(buffer2), 0, (struct sockaddr *)&m_servaddr, &addrlen);
