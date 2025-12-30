#include <stdio.h>
#include <stdint.h>

#include <x86intrin.h>

#define WAYS 8
#define SETS 64
#define LINE_SIZE 64
#define L1_SIZE (WAYS * SETS * LINE_SIZE)
// ADDRESS SECRET_KEY[0] -> 0x555555556008
// avg cache fetch time = 30 cycles

int probe_array[L1_SIZE];
int main() {
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
    return 0;
}

