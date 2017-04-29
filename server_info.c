#include <stdio.h>
#include <stdlib.h>
#include "inet_socket.h"

void main(int argc,char** argv){

	int fd=tcp_ip_socket();
	char *buffer="HEAD / HTTP/1.1\n\n",*info;
	connect_inet(fd,get_ip_by_name("google.com"),80);
	send_string(fd,buffer);
	while(info=recv_line(fd)){
		printf("%s\n",info);
		//free(info);//i have some problems with free()
	}

}
