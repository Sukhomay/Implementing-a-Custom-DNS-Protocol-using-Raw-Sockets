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

#define MAX_QRY_LIMIT 10
#define MAX_USR_QRY 1024
#define MAX_DOMAIN_LENGTH 31
#define MIN_DOMAIN_LENGTH 3

#define TWO_P_16 65536

typedef struct
{
    uint32_t size;       // 4 bytes for Size of the domain name in characters
    char *domainName; // Actual domain name (up to 32 bytes)
} Query;

typedef struct
{
    uint16_t id;             // 16 bits for ID
    uint8_t messageType; // 1 byte for Message Type (0: Query, 1: Response)
    uint8_t numQueries;  // 1 byte for Number of Queries (0-7)
    Query* queries;        // Array of up to 8 queries
} SimDNSQueryPacket;

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


typedef struct 
{
    int free;
    uint16_t id;
    SimDNSQueryPacket query;
    int sentCount; 
} userQuery;


char MY_IP_ADDR[20];
char MY_MAC_ADDR[30];

char SERVER_IP_ADDR[20];
char SERVER_MAC_ADDR[30];

#define INTERFACE "lo"

#define TIMEOUT 3

userQuery QueryTable[MAX_QRY_LIMIT];

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

int is_valid_domain(char *domain)
{
    // Check minimum and maximum length
    size_t length = strlen(domain);
    if (length < MIN_DOMAIN_LENGTH || length > MAX_DOMAIN_LENGTH)
    {
        return 0;
    }

    // Check for consecutive hyphens
    for (int i = 0; i < length - 1; i++)
    {
        if (domain[i] == '-' && domain[i + 1] == '-')
        {
            return 0;
        }
    }

    // Check for valid characters
    for (int i = 0; i < length; i++)
    {
        if (!isalnum(domain[i]) && domain[i] != '-' && domain[i] != '.')
        {
            return 0;
        }
    }

    // Check if hyphen is not at the beginning or end
    if (domain[0] == '-' || domain[length - 1] == '-')
    {
        return 0;
    }

    return 1;
}

// function to convert a domian query to a character array
void domain_converter(int32_t num, char *domain_name, char *result)
{
    result[0] = (num >> 24) & 0xFF;
    result[1] = (num >> 16) & 0xFF;
    result[2] = (num >> 8) & 0xFF;
    result[3] = num & 0xFF;

    strncpy(result + 4, domain_name, num);
}

// function to put unsigned long to a char array 
void ulongtoarray_48bit(unsigned long long num, char *arr)
{
    arr[0] = (num >> 40) & 0xFF;
    arr[1] = (num >> 32) & 0xFF;
    arr[2] = (num >> 24) & 0xFF;
    arr[3] = (num >> 16) & 0xFF;
    arr[4] = (num >> 8) & 0xFF;
    arr[5] = num & 0xFF;
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

// copy two character array
void chararrcpy(char *s1, char *s2, int size)
{
    for (int i = 0; i < size; i++)
    {
        s1[i] = s2[i];
    }
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

// function to send a DNS query
void send_DNSquery(int sockfd, SimDNSQueryPacket *query)
{
    unsigned char buffer[1024];

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

    ulongtoarray_48bit(mac_str_to_int(SERVER_MAC_ADDR), eth->h_dest);
    ulongtoarray_48bit(mac_str_to_int(MY_MAC_ADDR), eth->h_source);

    eth->h_proto = htons(ETH_P_ALL); // IP protocol

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
    ip->saddr = inet_addr(MY_IP_ADDR);     // replace with source IP
    ip->daddr = inet_addr(SERVER_IP_ADDR); // replace with destination IP
    ip->check = 0;                         // just for now, original after dataload

    // Prepare simDNS query
    simDNSQueryHeader *packet = (simDNSQueryHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    packet->id = query->id;
    packet->messageType = query->messageType;
    packet->numQueries = query->numQueries;

    // Preaparing simDNS query part
    char *data = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSQueryHeader);
    int offset = 0;
    for (int i = 0; i < query->numQueries; i++)
    {
        char domain_i[MAX_DOMAIN_LENGTH + sizeof(int) + 2];
        domain_converter(query->queries[i].size, query->queries[i].domainName, domain_i);

        chararrcpy(data + offset, domain_i, query->queries[i].size + sizeof(int));

        offset += query->queries[i].size + sizeof(int);
    }

    // other ip fields
    ip->tot_len = sizeof(struct iphdr) + sizeof(simDNSQueryHeader) + offset;
    ip->check = calculate_checksum(buffer + sizeof(struct ethhdr), ip->ihl * 4);

    // Send raw packet
    int bytes_sent = sendto(sockfd, buffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSQueryHeader) + offset, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent == -1)
    {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    if(argc!=5)
    {
        fprintf(stderr, "Please give <CLIENT MAC ADDR> <CLIENT IP ADDR> <SERVER MAC ADDR> <SERVER IP ADDR> in command line argument while executing. Exiting...\n");
    }
    
    strcpy(MY_MAC_ADDR, argv[1]);
    strcpy(MY_IP_ADDR, argv[2]);
    strcpy(SERVER_MAC_ADDR, argv[3]);
    strcpy(SERVER_IP_ADDR, argv[4]);

    int sockfd;
    struct sockaddr_ll dest_addr;                 // sockaddr_ll for raw socket
    unsigned char buffer[1024];                   // buffer for packet data
    const char *query_string = "www.example.com"; // simDNS query string

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Initialize the query table before taking any user input
    for (int i = 0; i < MAX_QRY_LIMIT; i++)
    {
        QueryTable[i].free = 1;
    }

    // Initial query id
    int curr_id = 1;

    fd_set rfds;
    int max_fd_value;
    int retval;
    struct timeval curr_time, timeout_duration, tv;

    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        if (sockfd > STDIN_FILENO)
            max_fd_value = sockfd;
        else
            max_fd_value = STDIN_FILENO;

        retval = select(max_fd_value + 1, &rfds, NULL, NULL, &tv);

        if (retval < 0)
        {
            perror("Select error");
            exit(EXIT_FAILURE);
        }
        else if (retval == 0)
        {
            // Timeout
            for (int i = 0; i < MAX_QRY_LIMIT; i++)
            {
                if (QueryTable[i].free == 1)
                    continue;

                if (QueryTable[i].sentCount == 4)
                {
                    printf("\n---------------------------------------------------------\n");
                    printf("Query ID: %d\n", QueryTable[i].id);
                    printf("Total query strings: %d\n\n", QueryTable[i].query.numQueries);
                    for (int k = 0; k < QueryTable[i].query.numQueries; k++)
                    {
                        char domain_name[MAX_DOMAIN_LENGTH + 2];
                        strncpy(domain_name, QueryTable[i].query.queries[k].domainName, QueryTable[i].query.queries[k].size);
                        domain_name[QueryTable[i].query.queries[k].size] = '\0';
                        printf("%s\n", domain_name);
                    }
                    printf("ERROR: No response received from the DNS server.\n");
                    printf("---------------------------------------------------------\n\n");
                    QueryTable[i].free = 1;
                    QueryTable[i].sentCount = 0;
                }
                else
                {
                    // resend queries
                    send_DNSquery(sockfd, &(QueryTable[i].query));
                    QueryTable[i].sentCount++;
                }
            }

            tv.tv_sec = TIMEOUT;
            tv.tv_usec = 0;
        }
        else
        {
            // Message typed at my end
            if (FD_ISSET(STDIN_FILENO, &rfds))
            {
                char usrQry[MAX_USR_QRY];
                fgets(usrQry, sizeof(usrQry), stdin);
                strtok(usrQry, "\n"); // Remove newline character

                // Extract N
                int N;
                char *token = strtok(usrQry, " ");
                if (token == NULL || strcmp(token, "getIP") != 0)
                {
                    if (strcmp(token, "EXIT") == 0)
                    {
                        printf("Exiting...\n");
                        close(sockfd);
                        exit(0);
                    }
                    printf("Invalid input format.\nEnter again...\n\n");
                    continue;
                }

                token = strtok(NULL, " ");
                if (token == NULL)
                {
                    printf("Invalid input format.\nEnter again...\n\n");
                    continue;
                }

                N = atoi(token);
                if (N <= 0 || N > 8)
                {
                    printf("Invalid value for N.\nEnter again...\n\n");
                    continue;
                }

                // Extract domain names
                char domains[N][MAX_DOMAIN_LENGTH + 1];
                int flag_allcorrect = 1;
                for (int i = 0; i < N; i++)
                {
                    token = strtok(NULL, " ");
                    if (token == NULL)
                    {
                        printf("Insufficient domain names provided.\nEnter again...\n\n");
                        flag_allcorrect = 0;
                        break;
                    }
                    else if (is_valid_domain(token) == 0)
                    {
                        printf("Domain name not it correct format.\nEnter again...\n\n");
                        flag_allcorrect = 0;
                        break;
                    }
                    else
                    {
                        strcpy(domains[i], token); // Allocate memory and copy domain name
                    }
                }
                if (!flag_allcorrect)
                    continue;

                int free_idx = -1;
                for (int j = 0; j < MAX_QRY_LIMIT; j++)
                {
                    if (QueryTable[j].free)
                    {
                        free_idx = j;
                        QueryTable[j].free = 0;
                        break;
                    }
                }

                if (free_idx == -1)
                {
                    printf("Try again after sometime... \n\n");
                    continue;
                }

                // update query table
                QueryTable[free_idx].id = curr_id;
                QueryTable[free_idx].sentCount = 1;
                QueryTable[free_idx].query.id = curr_id;
                QueryTable[free_idx].query.messageType = 0;
                QueryTable[free_idx].query.numQueries = N;
                QueryTable[free_idx].query.queries = (Query *)malloc(N * sizeof(Query));
                for (int j = 0; j < N; j++)
                {
                    QueryTable[free_idx].query.queries[j].size = strlen(domains[j]);
                    QueryTable[free_idx].query.queries[j].domainName = (char *)malloc(strlen(domains[j]) * sizeof(char));
                    strncpy(QueryTable[free_idx].query.queries[j].domainName, domains[j], strlen(domains[j]));
                }
                curr_id = (curr_id + 1) % TWO_P_16;
                send_DNSquery(sockfd, &(QueryTable[free_idx].query));
            }
            // Message is response
            else if (FD_ISSET(sockfd, &rfds))
            {
                unsigned int my_ip_addr = ip_str_to_int(MY_IP_ADDR);
                unsigned long long my_mac_addr = mac_str_to_int(MY_MAC_ADDR);
                unsigned long long broadcast_mac_addr = 0xFFFFFFFFFFFFULL;

                // Receive packet
                struct sockaddr_in local_addr;
                socklen_t local_addr_len = sizeof(local_addr);
                int packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&local_addr, &local_addr_len);

                if (packet_len == -1)
                {
                    perror("recvfrom");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }

                // Parse Ethernet header
                struct ethhdr *eth = (struct ethhdr *)buffer;
                if (ntohs(eth->h_proto) != ETH_P_ALL)
                {
                    continue;
                }

                if (byteArrayToInt_48bit(eth->h_dest) != mac_str_to_int(MY_MAC_ADDR) && byteArrayToInt_48bit(eth->h_dest) != mac_str_to_int("ff:ff:ff:ff:ff:ff"))
                {
                    continue;
                }

                // Parse IP header
                struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

                int prev_checksum = ip->check;
                ip->check = 0;
                int curr_checksum = calculate_checksum(buffer + sizeof(struct ethhdr), ip->ihl * 4);
                if (prev_checksum != curr_checksum)
                {
                    continue;
                }
                ip->check = curr_checksum;

                if (ip->protocol != 254 || (ip->daddr != my_ip_addr && ip->saddr != ip->daddr))
                {
                    continue;
                }

                SimDNSResponseHeader *header = (SimDNSResponseHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
                char *DNSdata = (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(SimDNSResponseHeader));

                int id = header->id;
                int messageType = header->messageType;

                if (messageType != 1)
                    continue;

                int flag_idpresent = 0;
                int qry_id = -1;
                int ndomain = 0;
                int idx = 0;
                for (idx = 0; idx < MAX_QRY_LIMIT; idx++)
                {
                    if (QueryTable[idx].free == 1)
                        continue;
                    if (QueryTable[idx].id == id && QueryTable[idx].sentCount > 0)
                    {
                        flag_idpresent = 1;
                        ndomain = QueryTable[idx].query.numQueries;
                        qry_id = QueryTable[idx].query.id;
                        break;
                    }
                }
                if (!flag_idpresent)
                    continue;

                // print response to user
                printf("\n---------------------------------------------------------\n");
                printf("Query ID: %d\n", qry_id);
                printf("Total query strings: %d\n\n", ndomain);
                for (int k = 0; k < ndomain; k++)
                {
                    char domain_name[MAX_DOMAIN_LENGTH + 2];
                    strncpy(domain_name, QueryTable[idx].query.queries[k].domainName, QueryTable[idx].query.queries[k].size);
                    domain_name[QueryTable[idx].query.queries[k].size] = '\0';

                    Response *response_k = (Response *)(DNSdata + k * sizeof(Response));
                    if (response_k->isValid == 0)
                    {
                        printf("%-31s   %-31s\n", domain_name, "NO IP ADDRESS FOUND");
                    }
                    else
                    {
                        struct in_addr addr;
                        addr.s_addr = response_k->ipAddress;
                        printf("%-31s   %-31s\n", domain_name, inet_ntoa(addr));
                    }
                }
                printf("---------------------------------------------------------\n\n");

                QueryTable[idx].free = 1;
                QueryTable[idx].sentCount = 0;
            }
        }
    }
}
