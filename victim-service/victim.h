#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// max users in regisrty
#define USER_COUNT 1
#define ROLE_COUNT 5

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
    char *roles[ROLE_COUNT];
    int role_usage[ROLE_COUNT * 4096]; // used for telemetry
};
extern struct RoleBinding role_binding;


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
void sign(char *username, char *role, unsigned char *signature);

// HTTP related
int get_POST_body(char *username, char *password, unsigned int *id, const char *buffer);
void http_response(char *response, int response_size, int status_code, char *message);