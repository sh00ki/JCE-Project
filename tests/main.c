#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/md5.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "radius.h"

 #define TOPORT 8615
 #define MYPORT 1812

 void my_ip( char *myniccard, char *myipaddr) {
      int fd;
      struct ifreq ifr;

      myipaddr[0]=0;

      fd = socket(AF_INET, SOCK_DGRAM, 0);

      /* I want to get an IPv4 IP address */
      ifr.ifr_addr.sa_family = AF_INET;

      /* I want IP address attached to "eth0" */
      //strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
      strncpy(ifr.ifr_name, myniccard, IFNAMSIZ-1);

      ioctl(fd, SIOCGIFADDR, &ifr);

      close(fd);

      /* display result */
      sprintf(myipaddr,"%s"
        , inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
      printf("MY IP address:%s: on port: %d\n", myipaddr, MYPORT);

      }   // my_ip

void print_bytes(unsigned char * c, int length) {
  int i;
  for(i = 0; i < length; i++) {
    printf("{%02x}", *(c + i));
  }
  printf("\n");
}
 int main(int argc, char *argv[ ])
 {
  unsigned int addr_len;
 int sockfd, sockfd1;
 struct sockaddr_in client_addr, server_addr,server_addr1;
 /* connectors address information */
 struct sockaddr_in their_addr;
 struct sockaddr_in localaddr;
 char myipaddressm[22];   //buffer for ip address
 char *myniccardm ="eth0";   // check with ipconfig for correct ethernet port
 Packet * request = (Packet *)malloc(MAX_LENGTH);
 Packet * respone = (Packet *)malloc(MAX_LENGTH);
 struct hostent *he;
 int numbytes;

 

 my_ip(myniccardm, myipaddressm);


 /* get the host info */
 if ((he = gethostbyname("130.211.107.8")) == NULL) {
      perror("Sender: Client-gethostbyname() error lol!");
      exit(1);
      }
  else
      printf("Sender: Client-gethostname() is OK...\n");

 if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
       perror("Sender: Client-socket() error lol!");
       exit(1);
       }
   else
       printf("Sender: Client-socket() sockfd is OK...\n");
  if((sockfd1 = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
       perror("Sender: Client-socket() error lol!");
       exit(1);
       }
   else
       printf("Sender: Client-socket() sockfd1 is OK...\n");


 // Bind to a specific network interface
 // (this is unusual, as you normally do not want a specific
 //  port for the client, but we have a specific server in
 //  this case that will not accept connects unless its on
 //  a specific port )
 localaddr.sin_family = AF_INET;
 localaddr.sin_addr.s_addr = inet_addr(myipaddressm);
 localaddr.sin_port = htons(MYPORT);  // Any local port will do
 server_addr.sin_family = AF_INET;
 server_addr.sin_port = htons(1811);
 server_addr.sin_addr.s_addr = INADDR_ANY;
 server_addr1.sin_family = AF_INET;
 server_addr1.sin_port = htons(8615);
 server_addr1.sin_addr.s_addr = INADDR_ANY;
 memset(&(server_addr.sin_zero), '\0', 8);
 bind(sockfd, (struct sockaddr *)&localaddr, sizeof(localaddr));
 if(bind(sockfd1, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
    printf("ERROR: bind\n");
    return EXIT_FAILURE;
  }


while(1){
 addr_len = sizeof(client_addr);
 if((numbytes = recvfrom(sockfd, request, sizeof(Packet), 0, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
      printf("ERROR: recvfrom\n");
      return EXIT_FAILURE;
    }
    printf("RECEIVED---\n");
      printf("code:\t\t{%02x}\n", request->code);
      printf("identifier:\t{%02x}\n", request->identifier);
      printf("length:\t\t%d\n", request->length);
      printf("authenticator:\t");
      print_bytes(request->authenticator, MD5_DIGEST_LENGTH);
      printf("-attributes-\n");
      printf("type:\t\t{%02x}\n", request->username.type);
      printf("length:\t\t%d\n", (int)request->username.length);
      printf("value:\t\t%s\n", request->username.value);
      printf("type:\t\t{%02x}\n", request->password.type);
      printf("length:\t\t%d\n", (int)request->password.length);
      printf("value:\t\t");
      print_bytes(request->password.value, MD5_DIGEST_LENGTH);
      printf("\n");
 /* host byte order */
 their_addr.sin_family = AF_INET;
 /* short, network byte order */
 printf("Sender: Using port: %d\n",TOPORT);
 their_addr.sin_port = htons(TOPORT);
 their_addr.sin_addr = *((struct in_addr *)he->h_addr);
 /* zero the rest of the struct */
 memset(&(their_addr.sin_zero), '\0', 8);

 if((numbytes = sendto(sockfd, request,sizeof(Packet),0,(struct sockaddr *)&their_addr,sizeof(struct sockaddr))) == -1) {
       perror("Sender: Client-sendto() error lol!");
       exit(1);
       }
   else
       printf("Sender: Client-sendto() is OK...\n");

  if ((he = gethostbyname("192.168.1.1")) == NULL) {
      perror("Sender: Client-gethostbyname() error lol!");
      exit(1);
      }
  else
      printf("Sender: Client-gethostname() is OK...\n");
 printf("Sender: sent %d bytes to %s\n", numbytes, inet_ntoa(their_addr.sin_addr));
 if((numbytes = recvfrom(sockfd, respone, sizeof(Packet), 0, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
      printf("0ERROR: recvfrom\n");
      return EXIT_FAILURE;
    }
    printf("%s\n", respone->authenticator);

 
//8615 -- 1812
 server_addr.sin_port = htons((unsigned short)1812);
 if((numbytes = sendto(sockfd, respone,sizeof(Packet),0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr))) == -1) {
       perror("1Sender: Client-sendto() error lol!");
       exit(1);
       }
   else
       printf("1Sender: Client-sendto() is OK...\n");

  if((numbytes = recvfrom(sockfd, request, sizeof(Packet), 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
      printf("1ERROR: recvfrom\n");
      return EXIT_FAILURE;
    }

  if((numbytes = sendto(sockfd, request,sizeof(Packet),0,(struct sockaddr *)&server_addr1,sizeof(struct sockaddr))) == -1) {
       perror("2Sender: Client-sendto() error lol!");
       exit(1);
       }
   else
       printf("2Sender: Client-sendto() is OK...\n");
}
  if((numbytes = recvfrom(sockfd, request, sizeof(Packet), 0, (struct sockaddr *)&server_addr1, &addr_len)) == -1) {
      printf("1ERROR: recvfrom\n");
      return EXIT_FAILURE;
    }
 return 0;

 }//main