#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "Sender.hpp"

#define PORT 8080
#define BUFFER_SIZE 1024

std::string_view ip_address = "127.0.0.1";

int main() {
    Sender s(ip_address, 8080);
    s.connect();
    // int sockfd;
    // char buffer[BUFFER_SIZE];
    // struct sockaddr_in servaddr;
    // std::cout << "Server started." << std::endl;
    // if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    //     perror("socket creation failed");
    //     exit(EXIT_FAILURE);
    // }

    // std::cout << sizeof(struct tcp_hdr) << std::endl;

    // memset(&servaddr, 0, sizeof(servaddr));

    // servaddr.sin_family = AF_INET;
    // servaddr.sin_port = htons(PORT);
    // servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // const char *message = "Hello, Server!";
    // int message_len = strlen(message);

    // struct iphdr *iph = (struct iphdr *)buffer;
    // std::cout << "iphdr - " <<sizeof(struct iphdr) << std::endl;
    // iph->ihl = 5;
    // iph->version = 4;
    // iph->tos = 0;
    // iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + message_len);
    // iph->id = htonl(54321);
    // iph->frag_off = 0;
    // iph->ttl = 255;
    // iph->protocol = IPPROTO_UDP;
    // iph->check = 0;
    // iph->saddr = inet_addr("127.0.0.1");
    // iph->daddr = servaddr.sin_addr.s_addr;

    // std::cout << "udphdr - " <<sizeof(struct udphdr) << std::endl;
    // struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct iphdr));
    // udph->source = htons(12345);
    // udph->dest = htons(PORT);
    // udph->len = htons(sizeof(struct udphdr) + message_len);
    // udph->check = 0;

    // memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), message, message_len);

    // if (sendto(sockfd, buffer, ntohs(iph->tot_len), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    //     perror("sendto failed");
    // } else {
    //     std::cout << "Message sent to server." << std::endl;
    // }

    // close(sockfd);
    return 0;
}



    // struct pseudo_header psh;
    // psh.source_address = inet_addr("127.0.0.1");
    // psh.dest_address = servaddr.sin_addr.s_addr;
    // psh.placeholder = 0;
    // psh.protocol = IPPROTO_UDP;
    // psh.udp_length = htons(sizeof(struct udphdr) + message_len);

    // int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + message_len;
    // char *pseudogram = new char[psize];

    // memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    // memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + message_len);

    // udph->check = checksum((void *)pseudogram, psize);

    // iph->check = checksum((void *)buffer, ntohs(iph->tot_len));
    // delete[] pseudogram;
    
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <arpa/inet.h>
// #include <netinet/ip.h>
// #include <netinet/udp.h>

// #define SERVER_IP "127.0.0.1"
// #define PORT 8080

// struct pseudo_header {
//     uint32_t source_address;
//     uint32_t dest_address;
//     uint8_t placeholder;
//     uint8_t protocol;
//     uint16_t udp_length;
// };

// unsigned short checksum(void *b, int len) {    
//     unsigned short *buf = (unsigned short *)b;
//     unsigned int sum = 0;
//     unsigned short result;

//     for (sum = 0; len > 1; len -= 2)
//         sum += *buf++;
//     if (len == 1)
//         sum += *(unsigned char *)buf;
//     sum = (sum >> 16) + (sum & 0xFFFF);
//     sum += (sum >> 16);
//     result = ~sum;
//     return result;
// }

// uint16_t calculate_checksum(const void* data, size_t length) {
//     uint32_t sum = 0;
//     const uint16_t* ptr = static_cast<const uint16_t*>(data);

//     while (length > 1) {
//         sum += *ptr++;
//         length -= 2;
//     }

//     if (length > 0) {
//         sum += *reinterpret_cast<const uint8_t*>(ptr);
//     }

//     while (sum >> 16) {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }

//     return static_cast<uint16_t>(~sum);
// }

// int main() {
//     int sockfd;
//     char buffer[4096];
//     struct iphdr *iph = (struct iphdr *) buffer;
//     struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr));
//     struct sockaddr_in dest_info;
//     struct pseudo_header psh;

//     sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
//     if (sockfd < 0) {
//         perror("socket creation failed");
//         exit(EXIT_FAILURE);
//     }

//     memset(buffer, 0, 4096);

//     // Fill in the IP Header
//     iph->ihl = 5;
//     iph->version = 4;
//     iph->tos = 0;
//     iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen("Hello, Server");
//     iph->id = htonl(54321);
//     iph->frag_off = 0;
//     iph->ttl = 255;
//     iph->protocol = IPPROTO_UDP;
//     iph->check = 0;
//     iph->saddr = inet_addr("127.0.0.1");
//     iph->daddr = inet_addr(SERVER_IP);

//     // IP checksum
//     iph->check = calculate_checksum((unsigned short *)buffer, iph->tot_len);

//     // UDP Header
//     udph->source = htons(12345);
//     udph->dest = htons(PORT);
//     udph->len = htons(8 + strlen("Hello, Server"));
//     udph->check = 0;

//     // Data part
//     strcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), "Hello, Server");

//     // Now the UDP checksum using the pseudo header
//     psh.source_address = inet_addr("127.0.0.1");
//     psh.dest_address = inet_addr(SERVER_IP);
//     psh.placeholder = 0;
//     psh.protocol = IPPROTO_UDP;
//     psh.udp_length = htons(sizeof(struct udphdr) + strlen("Hello, Server"));

//     int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen("Hello, Server");
//     char *pseudogram = (char *)malloc(psize);

//     memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
//     memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen("Hello, Server"));

//     udph->check = calculate_checksum((unsigned short *)pseudogram, psize);

//     dest_info.sin_family = AF_INET;
//     dest_info.sin_addr.s_addr = inet_addr(SERVER_IP);
//     dest_info.sin_port = htons(PORT);

//     // Send the packet
//     if (sendto(sockfd, buffer, iph->tot_len, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
//         perror("sendto failed");
//     }

//     printf("Packet Sent\n");

//     close(sockfd);
//     return 0;
// }
