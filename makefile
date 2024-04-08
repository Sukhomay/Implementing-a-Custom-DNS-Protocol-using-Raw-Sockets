client:
	sudo gcc simDNSClient.c -o simDNSClient
	sudo ./simDNSClient 90:e8:68:fa:9c:2b 127.0.0.1 90:e8:68:fa:9c:2b 127.0.0.1
server:
	sudo gcc simDNSServer.c -o simDNSServer
	sudo ./simDNSServer 90:e8:68:fa:9c:2b 127.0.0.1
clean:
	sudo rm simDNSClient simDNSServer