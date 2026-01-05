void cache_Measurement();
void check_cache_presence(int *count);
size_t write_junk(void *buffer, size_t size, size_t nmemb, void *userp);
void make_request(char *data);
uint64_t cache_threshold();
void prime_cache();