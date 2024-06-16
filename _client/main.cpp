#include <iostream>
#include <cstring>

#include "Sender.hpp"

#define PORT 8080
#define BUFFER_SIZE 1024

std::string_view ip_address = "127.0.0.1";

int main() {
    Sender s(ip_address, 8080);
    s.connect();
    // s.send("HELLO!!!");
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

// struct pseudo_header {
//     uint32_t source_address;
//     uint32_t dest_address;
//     uint8_t placeholder;
//     uint8_t protocol;
//     uint16_t udp_length;
// };

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
