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
#define KEY_SIZE 8

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

// loads set of users into memory
struct Users load_users(){
    users.users[0] = "user1";
    users.passwords[0] = "password";

    return users;
}

// responds to any request with fixed token from get_token() function
void launch(struct Server *server)
{
    
    int address_length = sizeof(server->address);
    while(1){
        char buffer[BUFFER_SIZE] = {0};
        char response[BUFFER_SIZE];
        printf("\n========== WAITING FOR CONNECTION ==========\n");
        //fflush(stdout);
        int new_socket = accept(server->socket, (struct sockaddr *)&server->address, (socklen_t *)&address_length);
        read(new_socket, buffer, BUFFER_SIZE);
        printf("%s\n", buffer);

        char *token = get_token("user1", "password");
        sprintf(response, 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s\n", 
            strlen(token) + 1, token);

        write(new_socket, response, strlen(response));
        close(new_socket);
    }
}

struct Users users;
// checks if username and password are correct
int check(char *username, char *password)
{
    if (strcmp(username, users.users[0]) == 0){
        if (strcmp(password, users.passwords[0]) == 0){
            return 1;
        }
    }

    return 0;
}

// will generate token using signing key and username
const uint8_t SIGNING_KEY[KEY_SIZE];
char * get_token(char *username, char *password)
{
    int result = check(username, password);
    if (result == 1){
        // get token
        char *token = "you got the token";
        return token;
    }
    return "wrong username or password";
}

int main(){
    // initialises server and opens server for connections
    struct Server server = server__constructor(AF_INET, 0, SOCK_STREAM, INADDR_ANY, PORT, 10, launch);
    // initialises user registry with one user
    users = load_users();
    server.launch(&server);
    return 0;
}