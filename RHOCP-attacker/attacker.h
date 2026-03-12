#include <netinet/in.h>

#define LINE_SIZE 64

typedef struct node {
    struct node *next;
    uint8_t padding[LINE_SIZE - sizeof(struct node*)]; // make 1 node = LINE_SIZE (64 bytes)
} node_t;

static inline __attribute__((always_inline)) void check_cache_presence(node_t *base_ptr, int *result);
static inline __attribute__((always_inline)) void prime_cache(node_t *base_ptr);
void get_inputs(char attack_data[], int argc, char* argv[]);
void shuffle(node_t **items, int item_count);
void open_socket(int *clientfd, struct sockaddr_in *servaddr);
void probe_arr_setup();

void byte_histogram(int *byte_diffs);

int address_in_set(node_t *address, node_t **current_set, int current_count);
int test_set(node_t *target, node_t **current_set, int current_count);
int full_test_set(node_t *target, node_t **current_set, int current_count);

int set_slice_exists(node_t **current_set, int found_slices, node_t **slice_sets);
void get_slice_sets(node_t **address_pool, node_t **slice_sets);
void build_dummy_slice_sets(uint8_t target_byte, node_t **slice_sets);