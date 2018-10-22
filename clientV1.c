#include<stdio.h>
#include<stdlib.h>

#include<sys/types.h>
#include<sys/socket.h>

#include<netinet/in.h>

int main() {

  // creating socket
  int network_socket;
  network_socket = socket(AF_INET, SOCK_STREAM, 0);

  //specify an address sturcture for the socket to connect to
  struct sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(9002);
  server_address.sin_addr.s_addr = INADDR_ANY;

  connect(network_socket, )
  return 0;
}
