#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "Reciever.hpp"

#define PORT 8080
#define BUFFER_SIZE 1024


// void parse_packet(const char *packet, pars &p, char *payload, size_t payload_size) {
//     memcpy(&p, packet, sizeof(pars));
//     std::cout << "test ||||" <<std::endl;
//     std::cout << "tcp->number - " << ntohs(p.tcp.number) << std::endl;
//     std::cout << "tcp->ack_number - " << ntohs(p.tcp.ack_number) << std::endl;
//     std::cout << "tcp->len - " << p.tcp.len << std::endl;
//     std::cout << "tcp->syn - " << p.tcp.syn << std::endl; 
//     std::cout << "test ||||" <<std::endl;
//     if(ntohs(p.tcp.syn) == 1)
//     {
//         //jjj
//     }
//     size_t headers_size = sizeof(pars);
//     size_t payload_len = payload_size - headers_size;
//     memcpy(payload, packet + sizeof(pars), payload_size);
//     std::cout << ntohs(p.ip.tot_len) << std::endl;
//     std::cout << ntohs(p.udp.len) << std::endl;
//     payload[payload_len] = '\0'; 
// }

int main() {
    Reciever r;
    r.connect();
    
    r.accept();
    // int sockfd;
    // struct sockaddr_in servaddr, cliaddr;

    // if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
    //     perror("socket creation failed");
    //     exit(EXIT_FAILURE);
    // }
    // std::cout << "iphdr - " <<sizeof(struct iphdr) << std::endl;
    // std::cout << "udphdr - " <<sizeof(struct udphdr) << std::endl;
    // std::cout << "tcp_hdr - " <<sizeof(struct tcp_hdr) << std::endl;
    // memset(&servaddr, 0, sizeof(servaddr));
    // memset(&cliaddr, 0, sizeof(cliaddr));

    // servaddr.sin_family = AF_INET;
    // servaddr.sin_addr.s_addr = INADDR_ANY;
    // servaddr.sin_port = htons(PORT);

    // if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    //     perror("bind failed");
    //     close(sockfd);
    //     exit(EXIT_FAILURE);
    // }
    // struct pars p;
    // while (true) {
    //     socklen_t len = sizeof(cliaddr);
    //     char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct tcp_hdr) + BUFFER_SIZE];
    //     char payload[BUFFER_SIZE];
    //     int n = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&cliaddr, &len);
    //     if (n > 0) {
    //         std::cout << "size n - " << n << std::endl;
    //         parse_packet(packet, p, payload, sizeof(payload));
    //         std::cout << "size packet - " << sizeof(packet) << std::endl;
    //         for(int i = 0;i < sizeof(packet); i++)
    //         {
    //             if(packet[i] == 'H')
    //             {
    //                 std::cout << i << std::endl;
    //             }
    //         }
    //         std::cout << std::endl;
    //         std::cout << "Received packet from client - " << std::string(payload) << std::endl;
    //     }
    // }
    // close(sockfd);
    return 0;
}


            // t.payload = p.payload;
            // std::cout << "test --\n";
            // std::cout << "Received packet from " << inet_ntoa(cliaddr.sin_addr) << std::endl;
            // std::cout << ntohs(t.ip.iph_sourceip) << std::endl;
            // std::cout << ntohs(t.ip.iph_ver) << std::endl;
            // std::cout << ntohl(ntohs(t.ip.iph_ident)) << std::endl;
            // std::cout << "n - " << n << std::endl;

            // struct ipheader *ip = (struct ipheader *)buffer;
            // int iphdr_len = ip->iph_ihl * 4;

            // struct udpheader *udp = (struct udpheader *)(buffer + iphdr_len);
            // int udphdr_len = sizeof(struct udpheader);

            // char *payload = buffer + iphdr_len + udphdr_len;
            // int payload_len = n - iphdr_len - udphdr_len;

            // if (payload_len > 0) {
            //     payload[payload_len] = '\0';
            //     std::string fff(payload);
            //     std::cout << "Client : " << fff << std::endl;
            // } else {
            //     std::cout << "No payload received." << std::endl;
            // }

            // memset(buffer, 0, sizeof(buffer));
            // n = 0;

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <arpa/inet.h>
// #include <netinet/ip.h>
// #include <netinet/udp.h>

// #define PORT 8080
// #define BUFSIZE 65536

// struct pseudo_header {
//     uint32_t source_address;
//     uint32_t dest_address;
//     uint8_t placeholder;
//     uint8_t protocol;
//     uint16_t udp_length;
// };

// int main() {
//     int sockfd;
//     char buffer[BUFSIZE];
//     struct sockaddr_in server_addr, client_addr;
//     socklen_t client_addr_len = sizeof(client_addr);
//     struct iphdr *iph = (struct iphdr *) buffer;
//     struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr));

//     sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
//     if (sockfd < 0) {
//         perror("socket creation failed");
//         exit(EXIT_FAILURE);
//     }

//     memset(&server_addr, 0, sizeof(server_addr));
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_addr.s_addr = INADDR_ANY;
//     server_addr.sin_port = htons(PORT);

//     while (1) {
//         int data_len = recvfrom(sockfd, buffer, BUFSIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len);
//         if (data_len < 0) {
//             perror("recvfrom error");
//             exit(EXIT_FAILURE);
//         }

//         iph = (struct iphdr *)buffer;
//         udph = (struct udphdr *)(buffer + iph->ihl * 4);
//         printf("Received packet from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(udph->source));

//         printf("Data: %s\n", buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
//     }

//     close(sockfd);
//     return 0;
// }
