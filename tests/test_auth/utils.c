#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include <openssl/md5.h>

#include "mradius.h"

#define SEP ": \n\t"
#define COMMENT_CHAR '#'

StringPair pa_parse(char * str, int sep) {
  StringPair sp;
  char * p;
  sp.first = str;
  sp.rest = NULL;

  p = strchr(str, sep);

  if(p) {
    *p = '\0';
    sp.rest = p + 1;
  }

  return sp;
}

Node * new_node(char * user, char * pass, Node * next) {
  Node * n = (Node *)malloc(sizeof(Node));
  memcpy(n->user, user, strlen(user));
  memcpy(n->pass, pass, strlen(pass));
  n->next = next;
  return n;
}

void print_nodes(Node * n) {
  Node * temp = (Node *)malloc(sizeof(Node));
  temp = n;

  while(temp != NULL) {
    printf("(%s, %s)\n", temp->user, temp->pass);
    temp = temp->next;
  }
}

Node * find_node(Node * root, char * user) {
  Node * temp = root;

  while(temp != NULL && strcmp(temp->user, user) != 0) {
    temp = temp->next;
  }

  return temp;
}

Node * parse_pwfile(char * filename) {
  Node * n = NULL;
  FILE * f;
  char s[1024];
  char u[1024], * u_temp;
  char p[1024], * p_temp;

  if (!(f = fopen(filename, "r"))) {
    return NULL;
  }

  while(fgets(s, sizeof(s), f)) {
    memset(u, 0, sizeof(u));
    memset(p, 0, sizeof(p));

    u_temp = strtok(s, SEP);
    if(!u_temp || *u_temp == COMMENT_CHAR) {
      continue;
    }
    memcpy(u, u_temp, strlen(u_temp));

    p_temp = strtok(NULL, SEP);
    if(!p_temp) {
      continue;
    }
    memcpy(p, p_temp, strlen(p_temp));

    n = new_node(u, p, n);

    if(g_verbose) {
      printf("%s:%d: adding (%s, %s) to linked list\n", __FILE__, __LINE__, n->user, n->pass);
    }
  }

  fclose(f);

  return n;
}

void print_bytes(unsigned char * c, int length) {
  int i;
  for(i = 0; i < length; i++) {
    printf("{%02x}", *(c + i));
  }
  printf("\n");
}

/* MD5 hash key + auth and put into digest */
void make_digest(unsigned char * key, int key_length, unsigned char * auth, int auth_length, unsigned char * digest) {
  unsigned char * cat_buffer = (unsigned char *)malloc(key_length + auth_length);
  unsigned char * hash_buffer = (unsigned char *)malloc(MD5_DIGEST_LENGTH);

  /* concatenate: key at beginning, auth at end */
  memcpy(cat_buffer, key, key_length);
  memcpy(cat_buffer + key_length, auth, auth_length);

  /* MD5 hash cat_buffer into hash_buffer */
  MD5(cat_buffer, key_length + auth_length, hash_buffer);

  /* put hash_buffer into digest */
  memcpy(digest, hash_buffer, MD5_DIGEST_LENGTH);

  free(cat_buffer);
  free(hash_buffer);
}

/* XOR digest and hash of password and put in pwd_buffer */
void xor(unsigned char * digest, unsigned char * pwd_hash, unsigned char * pwd_buffer) {
  unsigned char * buf = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  int i;

  for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
    memset(buf + i, *(digest + i) ^ *(pwd_hash + i), sizeof(char));
  }

  memcpy(pwd_buffer, buf, MD5_DIGEST_LENGTH);

  free(buf);
}
