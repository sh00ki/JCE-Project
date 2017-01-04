/* 
 * udpserver.c - A simple UDP echo server 
 * usage: udpserver <port>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 8192
#define MAX_LEN_RFC2865 4096
#define MIN_LEN_RFC2865 20


typedef struct radius_pack{
   int sockfd;
   char *src_ip;
   char *dst_ip;
   int src_port;
   int data_len;
}RADIUS_PACKET;

/*
 * error - wrapper for perror
 */
void error(char *msg) {
  perror(msg);
  exit(1);
}

int server_sendto_replay(int sockfd,RADIUS_PACKET *packet)
{
   void *temp = NULL;
   size_t length=1024;
   struct sockaddr sremote;


   int sentto_client_udp = sendto(sockfd,temp,length,0,&sremote,sizeof(struct sockaddr_in));
   if (sentto_client_udp<0)
   {
      printf("Error in sendto(server_sendto_replay)\n");
      return -1;
   }
   return 0;
}


int validate_packet_radius(RADIUS_PACKET *packet)
{
   if (packet->data_len < MIN_LEN_RFC2865) //by RFC 2865 the packet most be bigger then length = 20
      {
         printf("Error - RADIUS packet is too short, the min must to be bigger then 20\n");
         return -1;
      }
   if(packet->data_len > MAX_LEN_RFC2865) //by RFC 2865 the packet can be maximum 4096 
      {
         printf("Error - RADIUS packet is too long, the packet can be bigger then 4096\n");
         return -1;
      }
   return 0;
}


int main(int argc, char **argv) {
   int sockfd; /* socket */
   int portno = 1812; /* port to listen on */
   socklen_t clientlen; /* byte size of client's address */
   struct sockaddr_in serveraddr; /* server's addr */
   struct sockaddr_in clientaddr; /* client addr */
   struct hostent *hostp; /* client host info */
   char buf[BUFSIZE]; /* message buf */
   char *hostaddrp; /* dotted decimal host addr string */
   int optval; /* flag value for setsockopt */
   memset(buf,'\0',BUFSIZE);
   /* 
      * socket: create the parent socket 
   */
   sockfd = socket(AF_INET, SOCK_DGRAM, 0);
   if (sockfd < 0) 
      error("ERROR opening socket");

   /* setsockopt: Handy debugging trick that lets 
    * us rerun the server immediately after we kill it; 
    * otherwise we have to wait about 20 secs. 
    * Eliminates "ERROR on binding: Address already in use" error. 
   */
  optval = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

   /*
      * build the server's Internet address
   */
  bzero((char *) &serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); /* htonl is convert the unsined intger hostlong from host byte order to network byte order*/
  serveraddr.sin_port = htons((unsigned short)portno); /*htons is convert the unsigned short intger hostshort from host byte order to network byte*/


   /*
      bind: associate the parent socket with a port 
   */
      
   
   if (bind(sockfd, (struct sockaddr *) &serveraddr,sizeof(serveraddr)) < 0) 
      error("ERROR on binding");

  
   RADIUS_PACKET *packet = (RADIUS_PACKET*)malloc(sizeof(RADIUS_PACKET));
   if (packet == NULL)
    {
      printf("error with create packer (leak in memory)\n");
      return 1;
   }
   clientlen = sizeof(clientaddr);
   /* 
      * main loop: wait for a datagram, then echo it
   */
   while (1) {

      /*
        * recvfrom: receive a UDP datagram from a client
      */
       // printf("jsakjdsakjd\n");
      bzero(buf, BUFSIZE);
      packet->data_len = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr,&clientlen);
      if (packet->data_len < 0)
         error("ERROR in recvfrom");

      /* 
         * gethostbyaddr: determine who sent the datagram
      */
      hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,sizeof(clientaddr.sin_addr.s_addr), AF_INET);
      if (hostp == NULL)
         error("ERROR on gethostbyaddr");
      hostaddrp = inet_ntoa(clientaddr.sin_addr); // get the ip address of router
      if (hostaddrp == NULL)
         error("ERROR on inet_ntoa\n");
      printf("server received datagram from %s (%s)\n", hostp->h_name, hostaddrp);
      printf("server received %lu/%d bytes: %s\n", strlen(buf), packet->data_len, buf);
      packet->sockfd = sockfd;
      packet->src_ip = hostaddrp;
      packet->src_port = htons((unsigned short)portno);
      packet->dst_ip = serveraddr.sin_addr.s_addr;
      if (validate_packet_radius(packet) ==-1)
      {
         free(packet);
         break;
      }


     
      /* 
         * sendto: echo the input back to the client 
      
      n = sendto(sockfd, buf, strlen(buf), 0, 
      (struct sockaddr *) &clientaddr, clientlen);
      if (n < 0) 
         error("ERROR in sendto");
         */
  }
  return 0;
}