#include "inet_socket.h"

/*
	Create a new socket of IP protocol family and SOCK_STREAM type 
	return a file descriptor for the socket
	return -1 on failure
*/
int tcp_ip_socket(){
	return socket(PF_INET,SOCK_STREAM,0);
}



/*
	Create a new socket of IP protocol family and SOCK_DGRAM type 
	return a file descriptor for the socket
	return -1 on failure
*/
int udp_ip_socket(){
	return socket(PF_INET,SOCK_DGRAM,0);
}



/*
	Setup a socket (addr) with an ip address (ip) and a port number (port)
	the function setup the local ip address if ip==NULL
	return 1 on succes or 0 on failure
	print some error msg to the stderr in case of null pointer or malformed ip address
*/
int set_sockaddr_in(struct sockaddr_in *addr,char* ip,short port){

	if(addr==NULL){
		errno=EFAULT;
		perror("NULL socketaddr_in pointer");
		return 0;
	}

	addr->sin_family=AF_INET;
	addr->sin_port=htons(port);

	if(ip==NULL)
		addr->sin_addr.s_addr=0;
	
	else if(inet_aton(ip,&(addr->sin_addr))==0){
		errno=EINVAL;
		perror("Invalid ip addres");
		return 0;
	}

	memset(&(addr->sin_zero),'\0',8);

	return 1;

}



/*
	Wait for an incoming connexion to the socket described by the file descriptor (fd)
	write information about the incoming connexion on addr struct
	bind() and listen() must be called before
	return a file descriptor of the new connexion
	
	important: it wait until a valid connexion is set
*/
int wait_and_accept(int fd,struct sockaddr *addr,socklen_t *len){
	int new_fd=-1;

	while(new_fd==-1){
		new_fd=accept(fd,addr,len);
	}

	return new_fd;
}


/*
	Connect an internet socket (family PF_INET) described by the file descriptor (fd)
	to the remote host described by his ip address and port number
	return 0 on succes and -1 on failure
*/
int connect_inet(int fd,char* ip,short port){

	int result;

	struct sockaddr_in addr;
	set_sockaddr_in(&addr,ip,port);
	result=connect(fd,(struct sockaddr*)&addr,sizeof(struct sockaddr_in));

	return result; 

}

/*
	Perform a DNS lookup of a hostname and return his ip address
	return NULL on failure
*/
char* get_ip_by_name(char* name){

	char* ip=NULL;

	struct hostent* host=gethostbyname(name);

	if(host==NULL)
		return NULL;

	ip=inet_ntoa(*((struct in_addr*)host->h_addr));

	return ip;

}



/*
	i get send_string and recv_line from "The art of exploitation" book
	i did some modification on recv_line to avoid bof vuln
*/

/* This function accepts a socket FD and a ptr to the null terminated
* string to send. The function will make sure all the bytes of the
* string are sent. Returns 1 on success and 0 on failure.
*/
int send_string(int sockfd, unsigned char *buffer){
	
	int sent_bytes, bytes_to_send;
	bytes_to_send = strlen(buffer);
	while(bytes_to_send > 0) {
		sent_bytes = send(sockfd, buffer, bytes_to_send, 0);
		if(sent_bytes == -1)
			return 0; 
		bytes_to_send -= sent_bytes;
	buffer += sent_bytes;
	}
	return 1;
}


/* This function accepts a socket FD and a ptr to a destination
* buffer. It will receive from the socket until the EOL byte
* sequence in seen. The EOL bytes are read from the socket, but
* the destination buffer is terminated before these bytes.
* Returns the size of the read line (without EOL bytes).
*/
char* recv_line(int sockfd){

	#define EOL "\r\n" // End-of-line byte sequence
	#define EOL_SIZE 2

	unsigned char *dest_buffer=malloc(sizeof(char));
	unsigned char *ptr;

	int eol_matched = 0,count=0;
	ptr = dest_buffer;

	while(recv(sockfd, ptr, 1, 0) == 1) { // Read a single byte.

		dest_buffer=realloc(dest_buffer,sizeof(char)*(count+1));
		ptr = dest_buffer+count;

		if(*ptr == EOL[eol_matched]) { // Does this byte match terminator?
			eol_matched++;

			if(eol_matched == EOL_SIZE) { // If all bytes match terminator,
				*(ptr+1-EOL_SIZE) = '\0'; // terminate the string.
				return (strlen(dest_buffer)==0)?NULL:dest_buffer;
			}
		}else{
			eol_matched = 0;
		}

		ptr = dest_buffer+(++count);

	}

	return NULL; // Didn't find the end-of-line characters.

}

/*
Vulnerable to buffer over-flow

int recv_line(int sockfd, unsigned char *dest_buffer){

	#define EOL "\r\n" // End-of-line byte sequence
	#define EOL_SIZE 2

	unsigned char *ptr;
	int eol_matched = 0;
	ptr = dest_buffer;

	while(recv(sockfd, ptr, 1, 0) == 1) { // Read a single byte.

		if(*ptr == EOL[eol_matched]) { // Does this byte match terminator?
			eol_matched++;

			if(eol_matched == EOL_SIZE) { // If all bytes match terminator,
				*(ptr+1-EOL_SIZE) = '\0'; // terminate the string.
				return strlen(dest_buffer); // Return bytes received
			}
		}else{
			eol_matched = 0;
		}

		ptr++; // Increment the pointer to the next byter.

	}

	return 0; // Didn't find the end-of-line characters.

}*/


