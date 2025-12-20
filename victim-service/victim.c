#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "victim.h"

#define PORT 8080
#define BUFFER_SIZE 1024


struct Server server__constructor(int domain, int protocol, int type, in_addr_t interface, int port, int backlog, void(*launch)(struct Server *server))
{
    struct Server server;

    server.domain = domain;
    server.protocol = protocol;
    server.type = type;
    server.port = port;
    server.backlog = backlog;
    server.interface = interface;
    server.launch = launch;

    server.address.sin_family = domain;
    server.address.sin_port = htons(port); // converts to network address
    server.address.sin_addr.s_addr = htonl(interface);

    // creates socket: domain (IPv4 or 6), type (TCP or UDP), protocol
    server.socket = socket(domain, type, protocol);
    if (server.socket < 0){
        perror("Server socket connection failed.\n");
        exit(EXIT_FAILURE);
    }
    // bind socket to an address and port
    int binded = bind(server.socket, (struct sockaddr *)&server.address, sizeof(server.address));
    if (binded < 0){
        perror("Server socket binding failed.\n");
        exit(EXIT_FAILURE);
    }

    // await a connection
    if (listen(server.socket, server.backlog) < 0){
        perror("Server failed to start listening.\n");
        exit(EXIT_FAILURE);
    }
    printf("server is running on: http://localhost:%d\n", PORT);

    return server;
}


void launch(struct Server *server)
{
    // responds to any request with fixed token "93g2tg40gb3088t0g4h4"
    int address_length = sizeof(server->address);
    while(1){
        char buffer[BUFFER_SIZE] = {0};
        printf("\n========== WAITING FOR CONNECTION ==========\n");
        //fflush(stdout);
        int new_socket = accept(server->socket, (struct sockaddr *)&server->address, (socklen_t *)&address_length);
        read(new_socket, buffer, BUFFER_SIZE);
        printf("%s\n", buffer);

        char *response = "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 21\nConnection: close\n\n93g2tg40gb3088t0g4h4\n";
        write(new_socket, response, strlen(response));
        close(new_socket);
    }
}

int main(){
    // initialises server and opens server for connections
    struct Server server = server__constructor(AF_INET, 0, SOCK_STREAM, INADDR_ANY, 8080, 10, launch);
    server.launch(&server);
    return 0;
}
