#include <netinet/in.h>

#define LINE_SIZE 64

typedef struct node {
    struct node *next;
    uint8_t padding[LINE_SIZE - sizeof(struct node*)]; // make 1 node = LINE_SIZE (64 bytes)
} node_t;

void check_cache_presence(node_t *base_ptr, int *result);
void prime_cache(node_t *base_ptr);
void get_inputs(char attack_data[], int argc, char* argv[]);
void shuffle(int shuffle_arr[]);
void open_socket(int *clientfd, struct sockaddr_in *servaddr);
void probe_arr_setup();
node_t* build_linked_list(uint8_t target_byte);
uint64_t avg_hit_time(node_t *head);
int isAddressInteresting(node_t *addr);