#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#define USER_COUNT 1

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
struct Users users;
struct Users
{
    const char *users[USER_COUNT];
    const char *passwords[USER_COUNT];

};

// initialises server_constructor
struct Server server__constructor(int domain, int protocol, int type, 
    in_addr_t interface, 
    int port, int backlog, void(*launch)(struct Server *server));
    
void launch(struct Server *server);

//initialises users
struct Users load_users();

// token generator functions
int check(char *username, char *password);
char * get_token(char *username, char *password);