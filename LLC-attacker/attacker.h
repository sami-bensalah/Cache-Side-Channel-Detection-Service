#include <netinet/in.h>

void check_cache_presence(int *count);
void prime_cache(void);
void get_inputs(char attack_data[], int argc, char* argv[]);
void shuffle(int shuffle_arr[]);
void open_socket(int *clientfd, struct sockaddr_in *servaddr);
void linked_list();
