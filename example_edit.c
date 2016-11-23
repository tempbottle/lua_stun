#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#define debug(...) fprintf(stderr, __VA_ARGS__)
struct peer_addr {
    uint32_t in_addr;
    uint16_t port;
} mypeer[1];

static inline void die(const char *format, ...) __attribute__((format(printf, 1, 2), noreturn));
static inline void die(const char *format, ...)
{
    va_list va;
    va_start(va, format);
    vfprintf(stderr, format, va);
    va_end(va);
    exit(1);
}
static inline void fatal(const char *name) __attribute__((noreturn));
static inline void fatal(const char *name)
{
    perror(name);
    exit(1);
}
int connect_to_host(const char *node, const char *port, int sock_type)
{
    int res;
    struct addrinfo ar_request= { 0, AF_INET, sock_type }, *ar_result= 0;
    if( (res= getaddrinfo(node, port, &ar_request, &ar_result)) != 0 )
        die("Resolving %s: %s\n", node, gai_strerror(res));
    int sockfd= socket(ar_result->ai_addr->sa_family, ar_result->ai_socktype, ar_result->ai_protocol);
    if( sockfd<0 ) fatal("Create socket");
    if( connect(sockfd, ar_result->ai_addr, ar_result->ai_addrlen)<0 ) fatal("Connect socket");
    freeaddrinfo(ar_result);
    return sockfd;
}
struct stun_header {
    uint16_t msg_type;
    uint16_t data_len;
    uint32_t magick;
    uint32_t id[3];
    unsigned char data[];
};

void printhex (char *data, int len) {
	int i = 0;
	for (i = 0; i < len; i++) {
		printf("%02hhX", data[i]);
	}
}

void stun_req(int sockfd, struct peer_addr *peer)
{
    struct stun_header buf= { htons(1), 0, htonl(0x2112A442) }; // 1 - binding request
    int rndfd=open("/dev/urandom", 0);
    read(rndfd, (char*)buf.id, sizeof buf.id);
    close(rndfd);
    for( int attemp=0; attemp<5; attemp++ ) {

				// INVESTIGATION
				printf("Sending dgram to stun server: ");
				printhex((char *) &buf, sizeof buf);
				printf("\n");

        if( write(sockfd, &buf, sizeof buf) != sizeof buf ) fatal("Send STUN request");
        struct {
            struct stun_header hdr;
            unsigned char data[256];
        } rbuf;
        struct pollfd rfd= {sockfd, POLLIN};
        int ret=poll(&rfd, 1, 500);
        if( ret<0 ) fatal("STUN responce waiting");
        if( ret==0 ) continue;
        if( rfd.revents&(POLLERR|POLLNVAL|POLLHUP) ) die("Error during STUN responce wait\n");
        ret= read(sockfd, &rbuf, sizeof rbuf);
        if(ret<0) fatal("Read STUN response");
        if( rbuf.hdr.magick!=buf.magick || memcmp(buf.id, rbuf.hdr.id, sizeof buf.id) ) continue;
        for( int i=0; i<ret-20 && i<rbuf.hdr.data_len && rbuf.data[i+2]==0; i+= ((rbuf.data[i+2]*256+rbuf.data[i+3]+7)&~3) ) {

						// INVESTIGATION
						printf("parse: i = %d\n", i);

            debug("%x %d\n", rbuf.data[i]*256+rbuf.data[i+1], rbuf.data[i+2]*256+rbuf.data[i+3]);
            if(rbuf.data[i+2] || rbuf.data[i+3]==0 || ((i+rbuf.data[i+3]+7)&~3)>ret-20) continue;
            void debugIP(const char *name) {
                debug( "%1$s IPv%2$d %4$d.%5$d.%6$d.%7$d:%3$d\n", name, rbuf.data[i+5]*2+2, rbuf.data[i+6]*256+rbuf.data[i+7],
                 rbuf.data[i+8], rbuf.data[i+9], rbuf.data[i+10], rbuf.data[i+11] );
            }
            switch( rbuf.data[i]*256+rbuf.data[i+1] ) {
            case 0x8020:
                for(int j=0; j<2; j++) rbuf.data[i+6+j]^= ((char*)&rbuf.hdr.magick)[j];
                for(int j=0; j<rbuf.data[i+3]-4; j++) rbuf.data[i+8+j]^= ((char*)&rbuf.hdr.magick)[j];
                debug("XOR-");
            case 1: debugIP("MAPPED-ADDRESS");
                if(rbuf.data[i+5]==1) { // IPv4 only
                    peer->port= *(uint16_t*)(rbuf.data+i+6);
                    peer->in_addr= *(uint32_t*)(rbuf.data+i+8);
                }
                break;
            case 4: debugIP("SOURCE-ADDRESS");  break;
            case 5: debugIP("CHANGED-ADDRESS");  break;
            }
        }
        return;
    }
    die("STUN timeout\n");
}
int main(int argn, char **argv)
{
    if( argn!=2 ) die("usage: stun_cli <stun_server>\n");
    int sockfd= connect_to_host(argv[1], "3478", SOCK_DGRAM);
    stun_req(sockfd, mypeer);
}
