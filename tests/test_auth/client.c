#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/md5.h>

#include "mradius.h"

int mradius_client(struct Params * params) {
  struct sockaddr_in client_addr, server_addr;
  unsigned int client_port = 12345;
  unsigned int server_port = 1812;
  struct hostent * he;
  unsigned int numbytes, sockfd, i, addr_len, u_length, p_length, accept;
  unsigned char * digest = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char * auth = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char * pwd_hash = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char * xor_buffer = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  Packet * request = (Packet *)malloc(MAX_LENGTH);
  Packet * response = (Packet *)malloc(MAX_LENGTH);
  Attribute u, p;
  unsigned char * cat = (unsigned char *)malloc(MAX_LENGTH);
  unsigned char * response_auth = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  FILE * f;

  client_addr.sin_family = AF_INET;
  client_addr.sin_port = htons((short)client_port);
  client_addr.sin_addr.s_addr = INADDR_ANY;
  memset(&(client_addr.sin_zero), '\0', 8);

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons((short)server_port);
  server_addr.sin_addr.s_addr = INADDR_ANY;
  memset(&(server_addr.sin_zero), '\0', 8);

  if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    printf("ERROR: socket\n");
    return EXIT_FAILURE;
  }

  if(bind(sockfd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr)) == -1) {
    printf("ERROR: bind\n");
    return EXIT_FAILURE;
  }

  if((he = gethostbyname(params->host)) == NULL) {
    printf("ERROR: gethostbyname\n");
    return EXIT_FAILURE;
  }

  server_addr.sin_addr = *((struct in_addr *)he->h_addr);
  memset(&(server_addr.sin_zero), '\0', 8);

  /* fill auth */
  f = fopen("/dev/urandom", "r");
  if(g_norandomness) {
    memcpy(auth, "1234567891234567", MD5_DIGEST_LENGTH);
  } else {
    for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
      memset(auth + i, fgetc(f), sizeof(char));
    }
  }

  /* hash key + auth --> digest */
  make_digest(params->key, strlen(params->key), auth, MD5_DIGEST_LENGTH, digest);

  /* hash password --> pwd_hash */
  MD5(params->password, strlen(params->password), pwd_hash);

  /* XOR digest, pwd_hash --> xor_buffer */
  xor(digest, pwd_hash, xor_buffer);

  /* make Access-Request packet --> request */
  memset(u.value, '\0', MAX);
  u.type = USER_NAME;
  memcpy(u.value, params->username, strlen(params->username));
  u_length = sizeof(char) + sizeof(char) + strlen(u.value);
  u.length = (unsigned char)u_length;

  memset(p.value, '\0', MAX);
  p.type = USER_PASSWORD;
  memcpy(p.value, xor_buffer, MD5_DIGEST_LENGTH);
  p_length = sizeof(char) + sizeof(char) + MD5_DIGEST_LENGTH;
  p.length = (unsigned char)p_length;

  request->code = 0x01;
  request->identifier = fgetc(f);
  request->length = sizeof(char) + sizeof(char) + sizeof(short) + MD5_DIGEST_LENGTH + (int)u.length + (int)p.length;
  memcpy(request->authenticator, auth, MD5_DIGEST_LENGTH);
  request->username = u;
  request->password = p;
  memset(request->NAS_IP_Adress,'\0',MAX);
  strcpy (request->NAS_IP_Adress , "192.168.1.1");
  request->length = htons(request->length);

  /* send Access-Request packet */
  if((numbytes = sendto(sockfd, request, sizeof(Packet), 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))) == -1) {
    printf("ERROR: sendto\n");
    return EXIT_FAILURE;
  }

  request->length = ntohs(request->length);

  if(g_verbose) {
    printf("SENT---\n");
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
  }
  addr_len = sizeof(addr_len);
  /* receive reply */
  if((numbytes = recvfrom(sockfd, response, sizeof(Packet), 0, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
     printf("recv error%d\n",errno);
    printf("ERROR: recvfrom\n");
    return EXIT_FAILURE;
  }

  response->length = ntohs(response->length);

  if(g_verbose) {
    printf("RECEIVED---\n");
    printf("code:\t\t{%02x}\n", response->code);
    printf("identifier:\t{%02x}\n", response->identifier);
    printf("length:\t\t%d\n", response->length);
    printf("authenticator:\t");
    print_bytes(response->authenticator, MD5_DIGEST_LENGTH);
    printf("-attributes-\n");
    printf("type:\t\t{%02x}\n", response->username.type);
    printf("length:\t\t%d\n", (int)response->username.length);
    printf("value:\t\t%s\n", response->username.value);
    printf("type:\t\t{%02x}\n", response->password.type);
    printf("length:\t\t%d\n", (int)response->password.length);
    printf("value:\t\t");
    print_bytes(response->password.value, MD5_DIGEST_LENGTH);
    printf("\n");
  }

  /* decide if accept or reject */
  if(response->identifier != request->identifier) {
    printf("---NO---\n");
  } else {
    if(response->code == REJECT) {
      printf("---NO---\n");
    } else if(response->code == ACCEPT) {
      //cat = code + identifier + length + RequestAuth + attributes + secret
      //response_auth = MD5(cat)
      memset(cat, ACCEPT, 1);
      memset(cat + 1, request->identifier, 1);
      memset(cat + 2, (char)response->length, 2);
      memcpy(cat + 4, request->authenticator, MD5_DIGEST_LENGTH);
      memset(cat + 4 + MD5_DIGEST_LENGTH, request->username.type, 1);
      memset(cat + 5 + MD5_DIGEST_LENGTH, request->username.length, 1);
      memcpy(cat + 6 + MD5_DIGEST_LENGTH, request->username.value, strlen(request->username.value));
      memset(cat + 6 + MD5_DIGEST_LENGTH + strlen(request->username.value), request->password.type, 1);
      memset(cat + 7 + MD5_DIGEST_LENGTH + strlen(request->username.value), request->password.length, 1);
      memcpy(cat + 8 + MD5_DIGEST_LENGTH + strlen(request->username.value), request->password.value, strlen(request->password.value));
      memcpy(cat + 8 + MD5_DIGEST_LENGTH + strlen(request->username.value) + strlen(request->password.value), params->key, strlen(params->key));
      MD5(cat, 8 + MD5_DIGEST_LENGTH + strlen(request->username.value) + strlen(request->password.value) + strlen(params->key), response_auth);

      /* compare response->authenticator, response_auth */
      accept = 1;
      for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if(*(response->authenticator + i) != *(response_auth + i)) {
  	       accept = 0;
        }
      }

      if(accept) {
        printf("---YES---\n");
      } else {
        printf("---NO---\n");
      }
    }
  }

  free(digest);
  free(auth);
  free(pwd_hash);
  free(xor_buffer);
  free(request);
  free(response);
  free(cat);
  free(response_auth);
  fclose(f);
  close(sockfd);

  return EXIT_SUCCESS;
}
