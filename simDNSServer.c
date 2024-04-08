#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <ctype.h>
#include <time.h>
#include <netdb.h>

#define INTERFACE "lo"

#define DROP_PROB 0.3

#define MAX_QRY_LIMIT 30
#define MAX_USR_QRY 1024
#define MAX_DOMAIN_LENGTH 31
#define MIN_DOMAIN_LENGTH 3

#define TWO_P_16 65536


typedef struct
{
    uint16_t id;             // 16 bits for ID
    uint8_t messageType; // 1 byte for Message Type (0: Query, 1: Response)
    uint8_t numQueries;  // 1 byte for Number of Queries (0-7)
}simDNSQueryHeader;


typedef struct
{
    uint8_t isValid;     // 1 bit flag to indicate if it's a valid response
    uint32_t ipAddress; // 32 bits for IP address
} Response;

typedef struct
{
    uint16_t id;              // 16 bits for ID
    uint8_t messageType;  // 1 byte for Message Type (0: Query, 1: Response)
    uint8_t numResponses; // 1 byte for Number of Responses
} SimDNSResponseHeader;


char MY_IP_ADDR[20];
char MY_MAC_ADDR[30];


uint32_t ip_str_to_int(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) <= 0)
    {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return 0;
    }
    return addr.s_addr;
}

unsigned long long mac_str_to_int(const char *mac_str)
{
    unsigned long long mac_int = 0;
    int i;

    for (i = 0; i < 17; i += 3)
    {
        unsigned int byte;
        sscanf(mac_str + i, "%2x", &byte);
        mac_int = (mac_int << 8) | byte;
    }

    return mac_int;
}

void chararrcpy(char *s1, char *s2, int size)
{
    for (int i = 0; i < size; i++)
    {
        s1[i] = s2[i];
    }
}

void ulongtoarray_48bit(unsigned long long num, char *arr)
{
    arr[0] = (num >> 40) & 0xFF;
    arr[1] = (num >> 32) & 0xFF;
    arr[2] = (num >> 24) & 0xFF;
    arr[3] = (num >> 16) & 0xFF;
    arr[4] = (num >> 8) & 0xFF;
    arr[5] = num & 0xFF;
}

int32_t byteArrayToInt_32bit(unsigned char *byteArray)
{
    int32_t num = 0;

    num |= ((int32_t)byteArray[0] << 24);
    num |= ((int32_t)byteArray[1] << 16);
    num |= ((int32_t)byteArray[2] << 8);
    num |= (int32_t)byteArray[3];

    return num;
}

unsigned long long byteArrayToInt_48bit(unsigned char *byteArray)
{
    unsigned long long num = 0;
    
    num |= ((unsigned long long)byteArray[0] << 40);
    num |= ((unsigned long long)byteArray[1] << 32);
    num |= ((unsigned long long)byteArray[2] << 24);
    num |= ((unsigned long long)byteArray[3] << 16);
    num |= ((unsigned long long)byteArray[4] << 8);
    num |= (unsigned long long)byteArray[5];

    return num;
}

// function to get ip in int from from domain using gethostbyname
uint32_t ipfromhost(char *host)
{
    struct hostent *host_info;

    // Call gethostbyname to get host information
    host_info = gethostbyname(host);

    if (host_info == NULL)
    {
        return 0;
    }

    struct in_addr addr;
    memcpy(&addr, host_info->h_addr_list[0], sizeof(struct in_addr));
    uint32_t ip = addr.s_addr;
    return ip;
}

uint16_t calculate_checksum(const char *buffer, size_t length)
{
    uint32_t sum = 0;
    const uint16_t *data = (const uint16_t *)buffer;

    // Sum 16-bit words
    while (length > 1)
    {
        sum += *data;
        data = data + 1;
        length -= 2;
    }

    // Add the remaining byte if length is odd
    if (length == 1)
    {
        sum += *((const uint8_t *)data);
    }

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement of sum
    return ~sum;
}

// sending DNS response
void send_DNSresponse(int sockfd, char *DNSquerydata, simDNSQueryHeader *query_header, int32_t cli_ip, unsigned long long cli_mac)
{
    // send response
    char buffer[1024];

    // Set destination address and port
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_ifindex = if_nametoindex(INTERFACE); // replace with your network interface name
    dest_addr.sll_halen = ETH_ALEN;
    memset(dest_addr.sll_addr, 0xFF, ETH_ALEN); // destination MAC address (broadcast)

    // Prepare Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    ulongtoarray_48bit(cli_mac, eth->h_dest);
    ulongtoarray_48bit(mac_str_to_int(MY_MAC_ADDR), eth->h_source);
    eth->h_proto = htons(ETH_P_ALL);       // IP protocol

    // Prepare IP header
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    // ip->tot_len // total length
    ip->id = htons(0);
    ip->frag_off = htons(0);
    ip->ttl = 64;
    ip->protocol = 254;
    ip->saddr = inet_addr(MY_IP_ADDR);       // replace with source IP
    ip->daddr = cli_ip; // replace with destination IP
    ip->check = 0; // for now

    // Prepare simDNSResponse header
    SimDNSResponseHeader *response_header = (SimDNSResponseHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    response_header->id = query_header->id;
    response_header->messageType = 1;
    response_header->numResponses = query_header->numQueries;

    // Prepare simDNSResponse data
    int offset = 0;
    for (int i = 0; i < response_header->numResponses; i++)
    {
        int domain_length = byteArrayToInt_32bit(DNSquerydata + offset);
        char domain[MAX_DOMAIN_LENGTH + 1];
        chararrcpy(domain, DNSquerydata + offset + sizeof(int), domain_length);

        offset += domain_length + sizeof(int);

        domain[domain_length] = '\0';
        uint32_t ip = ipfromhost(domain);

        Response *response_i = (Response *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(SimDNSResponseHeader) + i * sizeof(Response));

        if (ip == 0)
        {
            response_i->isValid = 0;
        }
        else
        {
            response_i->isValid = 1;
        }
        response_i->ipAddress = ip;
    }

    // setting ip total length and checksum
    ip->tot_len = sizeof(struct iphdr) + sizeof(SimDNSResponseHeader) + response_header->numResponses * sizeof(Response);
    ip->check = calculate_checksum(buffer + sizeof(struct ethhdr), ip->ihl * 4);

    // Send raw packet
    int bytes_sent = sendto(sockfd, buffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(SimDNSResponseHeader) + response_header->numResponses * sizeof(Response), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent == -1)
    {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

int dropMessage(float p)
{
    float random_number = (float)(rand() % 1000) / 1000;

    if (random_number < p)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

    if(argc!=3)
    {
        fprintf(stderr, "Please give <SERVER MAC ADDR> <SERVER IP ADDR> in command line argument while executing. Exiting...\n");
    }

    strcpy(MY_MAC_ADDR, argv[1]);
    strcpy(MY_IP_ADDR, argv[2]);

    unsigned int my_ip_addr = ip_str_to_int(MY_IP_ADDR);
    unsigned long long my_mac_addr = mac_str_to_int(MY_MAC_ADDR);
    unsigned long long broadcast_mac_addr = 0xFF;

    // my_mac_addr = mac_str_to_int(argv[1]);

    int sockfd;
    struct sockaddr_in local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    unsigned char buffer[65536];           // buffer for packet data
    const char *interface_name = INTERFACE; // replace with your desired network interface name

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Bind raw socket to specific network interface
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) == -1)
    {
        perror("setsockopt");
        fprintf(stderr, "Error code: %d\n", errno);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Bound to interface: %s\n", interface_name);

    while (1)
    {
        // Receive packet
        int packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&local_addr, &local_addr_len);
        if (packet_len == -1)
        {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if(dropMessage((float)DROP_PROB)==1)
        {
            continue;
        }
        // Parse Ethernet header
        struct ethhdr *eth_header = (struct ethhdr *)buffer;

        if (ntohs(eth_header->h_proto) != ETH_P_ALL)
        {
            continue;
        }

        unsigned long long int eth_header_dest = byteArrayToInt_48bit(eth_header->h_dest);
        unsigned long long int eth_header_src = byteArrayToInt_48bit(eth_header->h_source);

        if (eth_header_dest != my_mac_addr && eth_header_dest != broadcast_mac_addr && eth_header_src != eth_header_dest)
        {
            // continue;
        }

        // Parse IP header
        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        int prev_checksum = ip_header->check;
        ip_header->check = 0;
        int curr_checksum = calculate_checksum(buffer + sizeof(struct ethhdr), ip_header->ihl * 4);

        if (prev_checksum != curr_checksum)
        {
            continue;
        }
        ip_header->check = curr_checksum;

        if (ip_header->protocol != 254)
        {
            continue;
        }

        if (ip_header->daddr != my_ip_addr && ip_header->saddr != ip_header->daddr)
        {
            continue;
        }

        // Parse the DNS header
        simDNSQueryHeader *DNSheader = (simDNSQueryHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if (DNSheader->messageType != 0)
        {
            continue;
        }

        char *DNSdata = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSQueryHeader);

        // Send the IP packet
        send_DNSresponse(sockfd, DNSdata, DNSheader, ip_header->saddr, eth_header_src);
    }

    close(sockfd);
    return 0;
}