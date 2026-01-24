#include <netinet/in.h>

void cache_Measurement(void);
void check_cache_presence(int *count);
size_t write_junk(void *buffer, size_t size, size_t nmemb, void *userp);
void make_request(char *data, int *clientfd);
int cache_threshold(void);
void prime_cache(void);
void get_inputs(char attack_data[], int argc, char* argv[]);
void invalid_request_baseline(int invalid_baseline[]);
void setup_linked_lists(void);
void shuffle(int shuffle_arr[]);

void open_socket(int *clientfd, struct sockaddr_in *servaddr);