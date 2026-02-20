#include <netinet/in.h>

#define LINE_SIZE 64

typedef struct node {
    struct node *next;
    uint8_t padding[LINE_SIZE - sizeof(struct node*)]; // make 1 node = LINE_SIZE (64 bytes)
} node_t;

void check_cache_presence(node_t *base_ptr, int *result);
void prime_cache(node_t *base_ptr);
void get_inputs(char attack_data[], int argc, char* argv[]);
void shuffle(node_t **items, int item_count);
void open_socket(int *clientfd, struct sockaddr_in *servaddr);
void probe_arr_setup();
node_t* build_linked_list(uint8_t target_byte);
uint64_t avg_hit_time(node_t *head);
int isAddressInteresting(node_t *addr);

void byte_histogram(int *byte_diffs);

node_t* get_perfect_eviction_set(node_t **address_pool);
int address_in_set(node_t *address, node_t **current_set, int current_count);
int test_set(node_t *target, node_t **current_set, int current_count);
int full_test_set(node_t *target, node_t **current_set, int current_count);
int is_set_useful(node_t *current_set);