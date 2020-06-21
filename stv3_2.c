/*
server.c -- a stream socket server program stable version - 3_2
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include<math.h>


#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10	 // how many pending connections queue will hold

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
	int sockfd, new_fd;                        // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;        // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while(1) {                                                                              // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);


		// Opening the file we are sending
		FILE *fp = fopen("sampleFile.txt", "rb");          // Open file to send
		if (fp == NULL){
		printf("File open error");
		return 1;
 }

		unsigned char enc_buff[256] = {0};

		// encrypt data funtion

			char *xor_encrypt(char data[]){    //array pointer return *xor_encrypt(return character pointer to string)

         int data_length = strlen(data);
         char key='@';
         int i;
         for(i=0;i<data_length;i++){
            data[i] = data[i]^key;
         }
         return data;
      }

			//send data on child process i.e. client


		if (!fork()) {                 // this is the child process
			close(sockfd); // child doesn't need the listener

		//	while(1){

        int x;
				void recva1(void){
				int rec_bytes_a1;
				rec_bytes_a1 = recv(new_fd, &x, sizeof(x), 0);
				printf("a1 recieved to server side \n");
				if (rec_bytes_a1 < 0){
					perror("recv_a1");
				  }
				sleep(3);
			  }


        void senda2(int x){
				if (x == 3){
					int y;
					y = x + 7;

          int bytes_sent_a2;

					bytes_sent_a2 = send(new_fd, &y, sizeof(y), 0);
					if (bytes_sent_a2 < 0){
						perror("send_a2");
					}
				}
				sleep(3);
			}

				int recva3(void){
				int rec_bytes_a3;
				int h;
				rec_bytes_a3 = recv(new_fd, &h, sizeof(h), 0);
				printf("a3 recieved to server side \n");
				if (rec_bytes_a3 < 0){
					perror("recv_a3");
				}
				sleep(3);
				return h;
			}

				int z;
				recva1();
				senda2(x);
				z = recva3();


				z = z - 1;

        if (z == 0)
				{
					printf("Authentication successful");


        unsigned char buff[256] = {0};                   // defining buffer for original file
				int nread = fread(buff, 1, 256, fp);           // reading data from original file into buffer
				printf("Bytes read %d \n", nread);
				buff[nread] = '\0';


				if (nread > 0){
					strcpy(enc_buff,buff);
					xor_encrypt(enc_buff);                       // read was successful or not
					printf("Bytes sending %d \n", nread);
					write(new_fd, enc_buff, nread);

				}

				if (nread < 256){                        // end of file reached or error before full read
					if (feof(fp))
						printf("End of file \n");
					if (ferror(fp))
					  printf("Error in reading from file\n");
	        break;
				}

			}
		  close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
	}
	return 0;
}
