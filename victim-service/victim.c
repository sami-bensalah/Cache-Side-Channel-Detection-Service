#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <sys/time.h>
#include <stdint.h>
#include <x86intrin.h>

#include "victim.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define RESPONSE_SIZE 1024
#define KEY_SIZE 8
#define USERNAME_MAX 16
#define PASSWORD_MAX 32
#define CACHE_STRIDE 1040

int attack_id = ((unsigned long)&layout.secret_key[0]-(unsigned long)&layout.role_binding.roles[0]);

struct Users users;

struct SharedMemory layout = {
    .role_binding.roles = {"guest", "user", "editor", "admin", "super"},
    .role_binding.role_count = ROLE_COUNT,
    .secret_key = {0x91, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
};


uint8_t *role_ptr;

int main(){
    // prints target byte that correct attack_id will speculativly load
    role_ptr = (uint8_t *)&layout.role_binding.roles; // gets base address of roles array first byte
    printf("LEAKED BYTE: 0x%x, Memory Address: %p -> Set %d\n", role_ptr[attack_id], &layout.role_usage[role_ptr[attack_id] * CACHE_STRIDE], calc_set(role_ptr));
    
    // mem address and attack id info
    printf("memory address of first byte signing key: %p\n", &layout.secret_key[0]);
    printf("memory address of start of roles array: %p\n", (void *)&layout.role_binding.roles[0]);
    printf("memory address of start of role_usage array: %p\n", (void *)&layout.role_usage[0]);
    printf("\nSigning Key Address in Dec: %lu \nRoles array Address in Dec: %lu\nDiff: %lu\n\n", (unsigned long)&layout.secret_key[0], (unsigned long)&layout.role_binding.roles[0], ((unsigned long)&layout.secret_key[0]-(unsigned long)&layout.role_binding.roles[0]));
    
    // initialises server and opens server for connections
    struct Server server = server__constructor(AF_INET, 0, SOCK_STREAM, INADDR_ANY, PORT, 10, launch);
    // initialises user registry with one user
    users = load_users();
    server.launch(&server);
    return 0;
}

int calc_set(uint8_t *role_ptr){
    uint8_t byte = role_ptr[attack_id];
    uintptr_t address = (uintptr_t)&layout.role_usage[byte * CACHE_STRIDE]; // get mem address it will map to 

    int set = (address >> 6) & 0x3F;
    return set;
}

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
        char response[RESPONSE_SIZE];
        printf("\n========== WAITING FOR CONNECTION ==========\n");
        //fflush(stdout);
        int new_socket = accept(server->socket, (struct sockaddr *)&server->address, (socklen_t *)&address_length);
        read(new_socket, buffer, BUFFER_SIZE);
        printf("%s\n", buffer);

        char username[USERNAME_MAX];
        char password[PASSWORD_MAX];
        unsigned int user_id;
        // gets params from POST body and assigns to local vars
        int status = get_POST_body(username, password, &user_id, buffer);
        if (status > 0){
            // sends result from get_token function
            char *data = get_token(username, password, user_id);
            http_response(response, RESPONSE_SIZE, 200, data);
        
        }
        else{
            // if POST request wrong
            http_response(response, RESPONSE_SIZE, 400, "Malformed POST request");
        }

        write(new_socket, response, strlen(response));
        close(new_socket);
    }
}

// generates response based on user credentials provided
char * get_token(char *username, char *password, unsigned int user_id)
{
    static char response[128];

    int result = check(username, password);

    // ===============  SPECTRE VULNERABILITY ===============
    _mm_clflush((void*)&layout.role_binding.role_count);
    _mm_mfence();

    if(user_id < layout.role_binding.role_count && result == 1){
        
        // * CACHE_STRIDE ensures each unqiue byte maps to unique cache set
        volatile uint8_t temp = layout.role_usage[role_ptr[user_id] * CACHE_STRIDE];
        
    // ======================================================
        temp = temp + 1;
        char *role = layout.role_binding.roles[user_id];
 

        // get token
        unsigned char signature[EVP_MAX_MD_SIZE];
        sign(username, role, signature);

        // converts token byte sequence to hex
        for (int i = 0; i < 32; i++){
            sprintf(&response[i * 2], "%02x\n", signature[i]);
        }
        response[65] = '\0';
        return response;
    }
    return "wrong username or password\n";

}

// returns 1 if username + password correct
int check(char *username, char *password)
{
    if (strcmp(username, users.users[0]) == 0){
        if (strcmp(password, users.passwords[0]) == 0){
            return 1;
        }
    }
    return 0;
}

// performs signature -> HMAC(SIGNING_KEY){username, role, timestamp}
void sign(char *username, char *role, unsigned char *signature){
    // create plaintext
    unsigned int sig_len;
    char plaintext[64]; // 16 chars (MAX_USERNAME) + 10 (ID) + 8 (timestamp) + 1 (null) - 64 for safety
    time_t currentTime;
    time(&currentTime); // Get the current time

    snprintf(plaintext, sizeof(plaintext),  "%s%s%s", username, role, ctime(&currentTime));

    HMAC(EVP_sha256(), layout.secret_key, KEY_SIZE, (const unsigned char *)plaintext, strlen(plaintext), signature, &sig_len);
}


int get_POST_body(char *username, char *password, unsigned int *id, const char *buffer)
{
    int found = 0;

    char *body = strstr(buffer, "\r\n\r\n");
    if(!body) return -1; // no body

    body +=4; // removes \r\n\r\n

    // get username, password and id
    char *user_ptr = strstr(body, "username=");
    if (user_ptr) {
        sscanf(user_ptr, "username=%15[^& ]", username); // read 15 chars up to '&'
        found ++;
    }

    char *pass_ptr = strstr(body, "password=");
    if (pass_ptr) {
        sscanf(pass_ptr, "password=%31[^& ]", password); // read 31 chars
        found ++;
    }

    char *id_ptr = strstr(body, "id=");
    if (id_ptr) {
        *id = atoi(id_ptr + 3); // convert id val to int
        found ++;
    }

    if (found == 3){
        return 1;
    }
    return 0;
} 


// builds http response
void http_response(char *response, int response_size, int status_code, char *message){
    const char *status_text;

    //get status code message
    switch (status_code) {
        case 200: status_text = "OK"; break;
        case 400: status_text = "Bad Request"; break;
        default:  status_text = "Unknown"; break;
    }

    // add status code and message to response
    snprintf(response, response_size,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code,
        status_text,
        strlen(message),
        message
    );
}


