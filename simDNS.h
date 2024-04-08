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
    uint8_t messageType; // 1 bit for Message Type (0: Query, 1: Response)
    uint8_t numQueries;  // 3 bits for Number of Queries (0-7)
    Query* queries;        // Array of up to 8 queries
} SimDNSQueryPacket;

typedef struct
{
    uint16_t id;             // 16 bits for ID
    uint8_t messageType; // 1 bit for Message Type (0: Query, 1: Response)
    uint8_t numQueries;  // 3 bits for Number of Queries (0-7)
}simDNSQueryHeader;


typedef struct
{
    uint8_t isValid;     // 1 bit flag to indicate if it's a valid response
    uint32_t ipAddress; // 32 bits for IP address
} Response;

typedef struct
{
    uint16_t id;              // 16 bits for ID
    uint8_t messageType;  // 1 bit for Message Type (0: Query, 1: Response)
    uint8_t numResponses; // 3 bits for Number of Responses
} SimDNSResponseHeader;


typedef struct 
{
    int free;
    uint16_t id;
    SimDNSQueryPacket query;
    int sentCount; 
} userQuery;


