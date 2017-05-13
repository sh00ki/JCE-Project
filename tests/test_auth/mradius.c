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

#include "mradius.h"

int g_verbose = 0;
int g_norandomness = 0;
int g_noloop = 0;

int main(int argc, char * argv[]) {
  int ch;
  int port = DEFAULT_PORT;
  char * hostname = (char *)malloc(MAX);
  Params * params = (Params *)malloc(sizeof(Params));
  char * user = (char *)malloc(MAX);
  char * pass = (char *)malloc(MAX);
  char * key = (char *)malloc(MAX);
  int client = 0;

  key = DEFAULT_SHARED_KEY;
 
  while((ch = getopt(argc, argv, "vRLk:p:h:")) != -1) {
    switch(ch) {
    case 'v':
      g_verbose++;
      break;
    case 'R':
      g_norandomness++;
      break;
    case 'L':
      g_noloop++;
      break;
    case 'k':
      key = strdup(optarg);
      break;
    case 'h':
      hostname = strdup(optarg);
      user = argv[optind];
      pass = argv[++optind];
      client = 1;
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case '?':
    default:
      printf("%s\n", USAGE_MESSAGE);
      return 0;
    }
  }
  argc -= optind;
  argv += optind;

  memset(params->host, '\0', MAX);

  params->no_randomness = g_norandomness;
  memcpy(params->host, hostname, strlen(hostname));
  params->port = port;
  strcpy(params->username, user);
  strcpy(params->password, pass);
  strcpy(params->key, key);
  
  if(!client) { //server
    Node * n;

    if(g_verbose) {
      printf("%s:%d: mradius_server, (|%s|)\n", __FILE__, __LINE__, argv[0]);
    }

    n = parse_pwfile(argv[0]);
    if(!n) {
      perror(argv[0]);
      return 0;
    }

    if(g_verbose) {
      print_nodes(n);
    }

    mradius_server(params, n);
  }
  else { //client
    mradius_client(params);
  }

  return EXIT_SUCCESS;
}
