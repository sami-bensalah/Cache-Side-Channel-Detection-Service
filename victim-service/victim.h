#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

// initialises server_constructor
struct Server server__constructor(int domain, int protocol, int type, 
    in_addr_t interface, 
    int port, int backlog, void(*launch)(struct Server *server));