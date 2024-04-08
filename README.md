# SimDNS Server and Client
This repository contains the implementation of a custom protocol called SimDNS, which functions similarly to DNS but in a simpler form. SimDNS consists of a server and a client component allowing users to query domain names and obtain corresponding IP addresses.

## Overview
SimDNS operates on top of IP packets using the protocol field 254. The server accepts SimDNS query packets, generates appropriate responses, and sends them back to the client. The client constructs and sends SimDNS query packets, receives and parses responses, and displays the corresponding IP addresses.

## Features
- **Server Implementation**: The SimDNS server captures and processes SimDNS query packets, generates appropriate responses, and sends them back to the client.
- **Client Implementation**: The SimDNS client constructs and sends SimDNS query packets, receives and parses responses, and displays the corresponding IP addresses.
- **Error Handling**: Both server and client perform validation of input data and handle errors gracefully.
- **Retransmission and Timeout Handling**: The client handles retransmission of queries and timeouts using the select() call.
- **Query Failure Testing**: The server includes a feature to simulate packet loss for testing purposes.

## Prerequisites
- C compiler (e.g., GCC)
- Linux environment (for raw socket programming) with sudo access

## Getting Started

1. Compile and run the server and client programs using the provided makefile in:
```bash
Run the server: make server
Run the client: make client
Clean         : make clean    
```
2. You can change the IP and MAC addresses of the server and client in the makefile

3. Default interface if "lo". You can change it server and client file separately as required in the macros.


