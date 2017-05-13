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
#include <openssl/hmac.h>

#include "mradius.h"

int mradius_server(struct Params * params, Node * ll_pwds) {
  struct sockaddr_in client_addr, server_addr;
  unsigned int addr_len, numbytes, sockfd, i, match, accept;
  Node * node = (Node *)malloc(sizeof(Node));
  Packet * request = (Packet *)malloc(MAX_LENGTH);
  unsigned char * digest = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char * pwd_hash = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char * xor_buffer = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char * cat = (unsigned char *)malloc(MAX_LENGTH);
  unsigned char * response_auth = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  Packet * response = (Packet *)malloc(MAX_LENGTH);
  char length_buffer[10];

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons((short)params->port);
  server_addr.sin_addr.s_addr = INADDR_ANY;
  memset(&(server_addr.sin_zero), '\0', 8);

  if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    printf("ERROR: socket\n");
    return EXIT_FAILURE;
  }

  if(bind(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
    printf("ERROR: bind\n");
    return EXIT_FAILURE;
  }
  memset(request->username.value,'\0',MAX);
  do {
    /* Receive Request */
    addr_len = sizeof(client_addr);
    if((numbytes = recvfrom(sockfd, request, sizeof(Packet), 0, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
      printf("ERROR: recvfrom\n");
      return EXIT_FAILURE;
    }
    
    request->length = ntohs(request->length);
    
    if(g_verbose) {
      printf("RECEIVED---\n");
      printf("code:\t\t{%02x}\n", request->code);
      printf("identifier:\t{%02x}\n", request->identifier);
      printf("length:\t\t%d\n", request->length);
      printf("authenticator:\t");
      print_bytes(request->authenticator, MD5_DIGEST_LENGTH);
      printf("-attributes-\n");
      printf("type:\t\t{%02x}\n", request->username.type);
      printf("length:\t\t%d\n", (int)request->username.length);
      printf("value:\t\t%c%c\n", request->username.value[0],request->username.value[1]);
      printf("type:\t\t{%02x}\n", request->password.type);
      printf("length:\t\t%d\n", (int)request->password.length);
      printf("value:\t\t");
      print_bytes(request->password.value, MD5_DIGEST_LENGTH);
      printf("\n");
    }
    //memset(request->username.value,'\0',MAX);
    unsigned  char *temp = (unsigned char*)calloc(MAX_LENGTH,sizeof(unsigned char));
    memset(temp,'\0',MAX_LENGTH);
    strncpy(temp, request->username.value, 2);
    printf("------------------------------------------\n");
    // strcpy(temp , request->username.value[0]);
    //strcat(request->username.value,request->username.value[1]);
    /* search for matching node in linked list */
    node = find_node(ll_pwds, temp);
    
    accept = 0;
    
    if(node == NULL) { //username not found
      printf("User Not Found\n");
      accept = 0;
    } else { 
	printf("User Found\n");//found username
      /* make digest --> digest */
      make_digest(params->key, strlen(params->key), request->authenticator, MD5_DIGEST_LENGTH, digest);
      
      /* hash password --> pwd_hash */
      MD5(node->pass, strlen(node->pass), pwd_hash);
      
      /* XOR digest, pwd_hash --> xor_buffer */
      xor(digest, pwd_hash, xor_buffer);
      
      /* compare xor_buffer, request->password.value */
      accept = 1;
      for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
	if(*(xor_buffer + i) != *(request->password.value + i)) {
	  accept = 0;
	}
      }
    }
    printf("make response packet\n");
    /* make response packet */
    if(accept) {
      response->code = 0x03;
    } else {
      response->code = 0x011;
    }
    
    response->identifier = request->identifier;
    response->length = sizeof(char) + sizeof(char) + sizeof(short) + MD5_DIGEST_LENGTH;
    unsigned char *authenticator_temp = NULL;
    //cat = code + identifier + length + RequestAuth + attributes + secret
    //response_auth = MD5(cat)
    // HMAC_CTX ctx;
    unsigned int len = 16;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, "2ZzMNRpKf574rGW", strlen("2ZzMNRpKf574rGW"), EVP_sha1(), NULL);
    HMAC_Update(&ctx, (unsigned char*)&response->authenticator, len);
    HMAC_Final(&ctx, response->authenticator, &len);
    HMAC_CTX_cleanup(&ctx);

    // unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, int n, 
    //unsigned char *md, unsigned int *md_len);
    // memset(cat, response->code, 1);
    // memset(cat + 1, response->identifier, 1);
    // memset(cat + 2, (char)response->length, 2);
    // memcpy(cat + 4, request->authenticator, MD5_DIGEST_LENGTH);
    // memset(cat + 4 + MD5_DIGEST_LENGTH, request->username.type, 1);
    // memset(cat + 5 + MD5_DIGEST_LENGTH, request->username.length, 1);
    // memcpy(cat + 6 + MD5_DIGEST_LENGTH, temp, strlen(temp));
    // memset(cat + 6 + MD5_DIGEST_LENGTH + strlen(temp), request->password.type, 1);
    // memset(cat + 7 + MD5_DIGEST_LENGTH + strlen(temp), request->password.length, 1);
    // memcpy(cat + 8 + MD5_DIGEST_LENGTH + strlen(temp), request->password.value, strlen(temp));
    // memcpy(cat + 8 + MD5_DIGEST_LENGTH + strlen(temp) + strlen(request->password.value), params->key, strlen(params->key));
    // MD5(cat, 8 + MD5_DIGEST_LENGTH + strlen(temp) + strlen(temp) + strlen(params->key), response_auth);
    //memcpy(response->authenticator, authenticator_temp, MD5_DIGEST_LENGTH);
    response->length = htons(response->length);
    
    /* send response packet */
    if((numbytes = sendto(sockfd, response, sizeof(Packet), 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr))) == -1) {
      printf("ERROR: sendto\n");
      return EXIT_FAILURE;
    }
    
    response->length = ntohs(response->length);
    
    if(g_verbose) {
      printf("SENT---\n");
      printf("code:\t\t{%02x}\n", response->code);
      printf("identifier:\t{%02x}\n", response->identifier);
      printf("length:\t\t%d\n", response->length);
      printf("authenticator:\t");
      print_bytes(response->authenticator, MD5_DIGEST_LENGTH);
      printf("-attributes-\n");
      printf("type:\t\t{%02x}\n", response->username.type);
      printf("length:\t\t%d\n", (int)response->username.length);
      printf("value:\t\t%s\n", temp);
      printf("type:\t\t{%02x}\n", response->password.type);
      printf("length:\t\t%d\n", (int)response->password.length);
      printf("value:\t\t");
      print_bytes(response->password.value, MD5_DIGEST_LENGTH);
      printf("\n");
    }
  } while(!g_noloop);
  
  free(request);
  free(digest);
  free(pwd_hash);
  free(xor_buffer);
  free(node);
  free(response);
  free(cat);
  free(response_auth);
  close(sockfd);

  return EXIT_SUCCESS;
}
