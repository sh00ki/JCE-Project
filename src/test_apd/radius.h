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
/* wpabuf::buf is a pointer to external data */
#define WPABUF_FLAG_EXT_DATA BIT(0)
#define MD5_MAC_LEN 16

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
static inline unsigned short wpa_swap_16(unsigned short v)
{
  return ((v & 0xff) << 8) | (v >> 8);
}
enum { RADIUS_ATTR_USER_NAME = 1,
       RADIUS_ATTR_USER_PASSWORD = 2,
       RADIUS_ATTR_NAS_IP_ADDRESS = 4,
       RADIUS_ATTR_NAS_PORT = 5,
       RADIUS_ATTR_FRAMED_MTU = 12,
       RADIUS_ATTR_REPLY_MESSAGE = 18,
       RADIUS_ATTR_STATE = 24,
       RADIUS_ATTR_CLASS = 25,
       RADIUS_ATTR_VENDOR_SPECIFIC = 26,
       RADIUS_ATTR_SESSION_TIMEOUT = 27,
       RADIUS_ATTR_IDLE_TIMEOUT = 28,
       RADIUS_ATTR_TERMINATION_ACTION = 29,
       RADIUS_ATTR_CALLED_STATION_ID = 30,
       RADIUS_ATTR_CALLING_STATION_ID = 31,
       RADIUS_ATTR_NAS_IDENTIFIER = 32,
       RADIUS_ATTR_PROXY_STATE = 33,
       RADIUS_ATTR_ACCT_STATUS_TYPE = 40,
       RADIUS_ATTR_ACCT_DELAY_TIME = 41,
       RADIUS_ATTR_ACCT_INPUT_OCTETS = 42,
       RADIUS_ATTR_ACCT_OUTPUT_OCTETS = 43,
       RADIUS_ATTR_ACCT_SESSION_ID = 44,
       RADIUS_ATTR_ACCT_AUTHENTIC = 45,
       RADIUS_ATTR_ACCT_SESSION_TIME = 46,
       RADIUS_ATTR_ACCT_INPUT_PACKETS = 47,
       RADIUS_ATTR_ACCT_OUTPUT_PACKETS = 48,
       RADIUS_ATTR_ACCT_TERMINATE_CAUSE = 49,
       RADIUS_ATTR_ACCT_MULTI_SESSION_ID = 50,
       RADIUS_ATTR_ACCT_LINK_COUNT = 51,
       RADIUS_ATTR_ACCT_INPUT_GIGAWORDS = 52,
       RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS = 53,
       RADIUS_ATTR_EVENT_TIMESTAMP = 55,
       RADIUS_ATTR_NAS_PORT_TYPE = 61,
       RADIUS_ATTR_TUNNEL_TYPE = 64,
       RADIUS_ATTR_TUNNEL_MEDIUM_TYPE = 65,
       RADIUS_ATTR_TUNNEL_PASSWORD = 69,
       RADIUS_ATTR_CONNECT_INFO = 77,
       RADIUS_ATTR_EAP_MESSAGE = 79,
       RADIUS_ATTR_MESSAGE_AUTHENTICATOR = 80,
       RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID = 81,
       RADIUS_ATTR_ACCT_INTERIM_INTERVAL = 85,
       RADIUS_ATTR_CHARGEABLE_USER_IDENTITY = 89,
       RADIUS_ATTR_NAS_IPV6_ADDRESS = 95,
       RADIUS_ATTR_ERROR_CAUSE = 101,
       RADIUS_ATTR_EAP_KEY_NAME = 102,
       RADIUS_ATTR_OPERATOR_NAME = 126,
       RADIUS_ATTR_LOCATION_INFO = 127,
       RADIUS_ATTR_LOCATION_DATA = 128,
       RADIUS_ATTR_BASIC_LOCATION_POLICY_RULES = 129,
       RADIUS_ATTR_EXTENDED_LOCATION_POLICY_RULES = 130,
       RADIUS_ATTR_LOCATION_CAPABLE = 131,
       RADIUS_ATTR_REQUESTED_LOCATION_INFO = 132,
       RADIUS_ATTR_MOBILITY_DOMAIN_ID = 177,
       RADIUS_ATTR_WLAN_HESSID = 181,
       RADIUS_ATTR_WLAN_PAIRWISE_CIPHER = 186,
       RADIUS_ATTR_WLAN_GROUP_CIPHER = 187,
       RADIUS_ATTR_WLAN_AKM_SUITE = 188,
       RADIUS_ATTR_WLAN_GROUP_MGMT_CIPHER = 189,
};
typedef unsigned u8;
typedef unsigned u32;
#define be_to_host16(n) wpa_swap_16(n)
struct MD5Context {
  u32 buf[4];
  u32 bits[2];
  u8 in[64];
};

struct radius_client;
struct radius_server_data;

/**
 * struct radius_server_counters - RADIUS server statistics counters
 */
struct radius_server_counters {
  u32 access_requests;
  u32 invalid_requests;
  u32 dup_access_requests;
  u32 access_accepts;
  u32 access_rejects;
  u32 access_challenges;
  u32 malformed_access_requests;
  u32 bad_authenticators;
  u32 packets_dropped;
  u32 unknown_types;

  u32 acct_requests;
  u32 invalid_acct_requests;
  u32 acct_responses;
  u32 malformed_acct_requests;
  u32 acct_bad_authenticators;
  u32 unknown_acct_types;
};

/**
 * struct radius_session - Internal RADIUS server data for a session
 */
struct radius_session {
  struct radius_session *next;
  struct radius_client *client;
  struct radius_server_data *server;
  unsigned int sess_id;
  struct eap_sm *eap;
  struct eap_eapol_interface *eap_if;
  char *username; /* from User-Name attribute */
  char *nas_ip;

  struct radius_msg *last_msg;
  char *last_from_addr;
  int last_from_port;
  struct sockaddr_storage last_from;
  socklen_t last_fromlen;
  u8 last_identifier;
  struct radius_msg *last_reply;
  u8 last_authenticator[16];

  unsigned int remediation:1;
  unsigned int macacl:1;

  struct hostapd_radius_attr *accept_attr;
};

/**
 * struct radius_client - Internal RADIUS server data for a client
 */
struct radius_client {
  struct radius_client *next;
  struct in_addr addr;
  struct in_addr mask;
#ifdef CONFIG_IPV6
  struct in6_addr addr6;
  struct in6_addr mask6;
#endif /* CONFIG_IPV6 */
  char *shared_secret;
  int shared_secret_len;
  struct radius_session *sessions;
  struct radius_server_counters counters;
};
