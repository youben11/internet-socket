#ifndef DEF_INET_SOCKET
#define DEF_INET_SOCKET

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

int tcp_ip_socket();
int udp_ip_socket();
int set_sockaddr_in(struct sockaddr_in *addr,char* ip,short port);
int wait_and_accept(int fd,struct sockaddr *addr,socklen_t *len);
int connect_inet(int fd,char* ip,short port);
char* get_ip_by_name(char* name);
int send_string(int sockfd, unsigned char *buffer);
char* recv_line(int sockfd);

#endif