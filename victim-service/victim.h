#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// max users in regisrty
#define USER_COUNT 1
#define ROLE_COUNT 5
#define ROLE_SIZE 16

// server object
struct Server
{
    int domain;
    int protocol;
    int type;
    in_addr_t interface;
    int port;
    int backlog;
    struct sockaddr_in address;

    void (*launch)(struct Server *server);

    int socket;

};

// user password store object
struct Users
{
    const char *users[USER_COUNT];
    const char *passwords[USER_COUNT];
};
extern struct Users users;

// role store object
struct RoleBinding{
    // both byte aligned to ensure that set mapping is reliable
    uint8_t roles[ROLE_COUNT] __attribute__((aligned(4096)));
    uint8_t padding[128]; // prevents role_count being loaded into cache due to roles[]
    unsigned int role_count;
  
};

// forces key to come after roles array in memory
struct SharedMemory {
    struct RoleBinding role_binding;
    uint8_t padding1[128];
    uint8_t secret_key[8]; 
    uint8_t padding2[256];
    uint8_t *role_usage; // used for telemetry
}__attribute__((packed));
extern struct SharedMemory layout;

// initialises server_constructor
struct Server server__constructor(int domain, int protocol, int type, 
    in_addr_t interface, 
    int port, int backlog, void(*launch)(struct Server *server));
    
void launch(struct Server *server);

//initialises users
struct Users load_users();

// token generator functions
int check(char *username, char *password);
char * get_token(char *username, char *password, unsigned int user_id);
void sign(char *username,  uint8_t role, unsigned char *signature);

// HTTP related
int get_POST_body(char *username, char *password, unsigned int *id, const char *buffer);
void http_response(char *response, int response_size, int status_code, char *message);

void calc_set();
void spectre_flush_reload();