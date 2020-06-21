/*
 client.c -- a stream socket client program stable Version - 3_2
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define PORT "3490" // the port client will be connecting to

#define MAXDATASIZE 256 // max number of bytes we can get at once

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;
	char buff[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 2) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

  void senda1(void){
	int x = 3;
	int bytes_sent_a1;

	bytes_sent_a1 = send(sockfd, &x, sizeof(x), 0);
	if (bytes_sent_a1 < 0){
		perror("send_a1");
	 }
	sleep(3);
 }

	int y;
	void recva1(void){
	int rec_bytes_a2;
	rec_bytes_a2 = recv(sockfd, &y, sizeof(y), 0);
	printf("a2 recieved to client side \n");
	if (rec_bytes_a2 < 0){
		perror("recv_a2");
	 }
	sleep(3);
}

  void senda3(int y){
	if(y == 10){
		   int h;
	     h = y/10;
		 	 int bytes_sent_a3;

		 	 bytes_sent_a3 = send(sockfd, &h, sizeof(h), 0);
		 	 if (bytes_sent_a3 < 0){
		 		 perror("send_a3");
		 	 }
	sleep(3);
	  }
}

senda1();
recva1();
senda3(y);





	FILE *fp = fopen("sampleFile.txt","ab");
	if (fp == NULL){
		printf("Error opening file");
		return 1;
	}

	unsigned char dec_buff[256] = {0};

	char *xor_decrypt(char data[]){    //array pointer return *xor_encrypt(return character pointer to string)

		 int data_length = strlen(data);
		 char key='@';
		 int i;
		 for(i=0;i<data_length;i++){
				data[i] = data[i]^key;
		 }
		 return data;
	}

  memset(buff, '0', sizeof(buff));
	if ((numbytes = read(sockfd, buff, MAXDATASIZE)) > 0) {
		printf("Bytes recieved %d\n", numbytes);
	}

	if (numbytes < 0){
		printf("\n Read Error\n");
	}
	else{
		printf("File recieved");
		xor_decrypt(buff);
		fwrite(buff, 1, numbytes, fp);
		fclose(fp);
	}

	// buf[numbytes] = '\0';

	close(sockfd);

	return 0;
}
