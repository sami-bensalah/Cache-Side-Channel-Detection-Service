#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#define PORT 8080
#define INET "127.0.0.1"


void open_socket(int *clientfd, struct sockaddr_in *servaddr){
    *clientfd = socket(AF_INET, SOCK_STREAM, 0);

    servaddr->sin_family = AF_INET;
    servaddr->sin_port = htons(PORT);
    servaddr->sin_addr.s_addr = inet_addr(INET);
}


void send_request(int *clientfd){
    char buf[256] = {0};
    
    
    char *request;
    char *g_request = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 37\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=user1&password=password&id=2";

    char *b_request = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 37\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=kdfds&password=hgsvhfbk&id=2";
    srand(time(NULL));
    if (rand()%2 == 0){
        request = g_request;
        printf("G REQUEST\n");
    }else{
        request = b_request;
        printf("B REQUEST\n");
    }
    send(*clientfd, request, strlen(request), 0);
    recv(*clientfd, buf, sizeof(buf), 0); 
    
    printf(buf);
}


int clientfd;

int main() {
    struct sockaddr_in servaddr;
    open_socket(&clientfd, &servaddr);
    connect(clientfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    // sends reqs
    while(1){
        usleep(5000); // pause
        send_request(&clientfd);
        //close(clientfd);
    }
}