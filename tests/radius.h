#define USAGE_MESSAGE "usage: mradius [-vLR -k key -p port] (-h host user pwd | pwd-file)"
#define DEFAULT_PORT  1812
#define DEFAULT_SHARED_KEY "pa55word0"
#define REQUEST '1'
#define ACCEPT '2'
#define REJECT '3'
#define MAX_LENGTH 4096
#define MAX 256
#define USER_NAME '1'
#define USER_PASSWORD '2'
#define AUTH_LENGTH 16

extern int g_verbose;
extern int g_norandomness;
extern int g_noloop;

typedef struct {
  unsigned char * first;
  unsigned char * rest;
} StringPair;

typedef struct Node {
  char user[1024];
  char pass[1024];
  struct Node * next;
} Node;

typedef struct Params {
  unsigned char host[MAX];
  int port;
  int no_randomness;
  /* add more parameters here, if needed */
  unsigned char key[MAX];
  unsigned char username[MAX];
  unsigned char password[MAX];
} Params;

typedef struct {
  unsigned char type;
  unsigned char length;
  unsigned char value[MAX];
} Attribute;

typedef struct {
  unsigned char code;
  unsigned char identifier;
  short length;
  unsigned char authenticator[AUTH_LENGTH];
  Attribute username;
  Attribute password;
} Packet;

StringPair pa_parse(char * str, int sep);
Node * new_node(char * user, char * pass , Node * next);
Node * find_node(Node * root, char * user);
Node * parse_pwfile(char * filename);
void print_nodes(Node * n);
void print_bytes(unsigned char * c, int length);
void make_digest(unsigned char * key, int key_length, unsigned char * auth, int auth_length, unsigned char * digest);
void xor(unsigned char * digest, unsigned char * pwd_hash, unsigned char * pwd_buffer);

int mradius_client(struct Params * params);
int radius_server(struct Params * params, Node * ll_pwds);
