
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <talloc.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "server.h"
#include "slist.h"
#define TESTSTRING "ACCESS-ACCEPT"
#include <openssl/md5.h>
#include <openssl/hmac.h>


static _Thread_local fr_randctx fr_rand_pool;   //!< A pool of pre-generated random integers
static _Thread_local bool fr_rand_initialized = false;
void fr_rand_seed(void const *data, size_t size);

typedef struct fr_dict fr_dict_t;
struct dict_attr {
  unsigned int    vendor;       //!< Vendor that defines this attribute.
  unsigned int    attr;       //!< Attribute number.
  PW_TYPE     type;       //!< Value type.

  fr_dict_attr_t const  *parent;      //!< Immediate parent of this attribute.
  fr_dict_attr_t const  **children;     //!< Children of this attribute.
  fr_dict_attr_t const  *next;        //!< Next child in bin.

  unsigned int    depth;        //!< Depth of nesting for this attribute.

  fr_dict_attr_flags_t  flags;        //!< Flags.
  char      name[1];      //!< Attribute name.
};

typedef struct value_pair {
  fr_dict_attr_t const    *da;        //!< Dictionary attribute defines the attribute
                //!< number, vendor and type of the attribute.

  struct value_pair *next;

  FR_TOKEN    op;       //!< Operator to use when moving or inserting
                //!< valuepair into a list.

  int8_t      tag;        //!< Tag value used to group valuepairs.

  union {
  //  VALUE_SET *set;       //!< Set of child attributes.
  //  VALUE_LIST  *list;        //!< List of values for
                //!< multivalued attribute.
  //  value_box_t *data;        //!< Value data for this attribute.

    char const  *xlat;        //!< Source string for xlat expansion.
  };

  value_type_t    type;       //!< Type of pointer in value union.
  value_box_t   data;
} VALUE_PAIR;

typedef struct fr_ipaddr_t {
  int   af;     //!< Address family.
  union {
    struct in_addr  ip4addr;    //!< IPv4 address.
    struct in6_addr ip6addr;    //!< IPv6 address.
  } ipaddr;
  uint8_t   prefix;           //!< Prefix length - Between 0-32 for IPv4 and 0-128 for IPv6.
  uint32_t  zone_id;    //!< A host may have multiple link-local interfaces
            //!< the scope ID allows the application to specify which of
            //!< those interfaces the IP applies to.  A special scope_id
            //!< of zero means that any interface of a given scope can
            //!< be used.
} fr_ipaddr_t;

typedef struct radius_packet {
  struct sockaddr_storage  cli;
  socklen_t cli_len;
  int     sockfd;     //!< Socket this packet was read from.
  int     if_index;   //!< Index of receiving interface.
  fr_ipaddr_t   src_ipaddr;   //!< Src IP address of packet.
  fr_ipaddr_t   dst_ipaddr;   //!< Dst IP address of packet.
  uint16_t    src_port;   //!< Src port of packet.
  uint16_t    dst_port;   //!< DST Port of packet.

  int     id;     //!< Packet ID (used to link requests/responses).
  unsigned int    code;     //!< Packet code (type).

  uint8_t     vector[AUTH_VECTOR_LEN];//!< RADIUS authentication vector.

  uint32_t          count;      //!< Number of times we've seen this packet
  struct timeval    timestamp;    //!< When we received the packet.
  uint8_t     *data;      //!< Packet data (body).
  size_t      data_len;   //!< Length of packet data.
  VALUE_PAIR    *vps;     //!< Result of decoding the packet into VALUE_PAIRs.
  ssize_t     offset;
  uint8_t buf[BUFSIZE];
  uint32_t          rounds;     //!< for State[0]

} RADIUS_PACKET;

int fr_ipaddr_from_sockaddr(struct sockaddr_storage const *sa, socklen_t salen, fr_ipaddr_t *ipaddr, uint16_t *port);
bool fr_radius_ok(RADIUS_PACKET *packet, bool require_ma, decode_fail_t *reason);
uint32_t fr_max_attributes = 0;
FILE *fr_log_fp = NULL;
static void print_hex_data(uint8_t const *ptr, int attrlen, int depth);
void fr_radius_print_hex(RADIUS_PACKET const *packet);
int fr_ipaddr_to_sockaddr(fr_ipaddr_t const *ipaddr, uint16_t port, struct sockaddr_storage *sa, socklen_t *salen);
int sendfromto(int fd, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t from_len, struct sockaddr *to, socklen_t to_len, int if_index);
ssize_t udp_send(int sockfd, void *data, size_t data_len, int flags,
     UDP_UNUSED fr_ipaddr_t *src_ipaddr, UDP_UNUSED uint16_t src_port, UDP_UNUSED int if_index,
     fr_ipaddr_t *dst_ipaddr, uint16_t dst_port);
uint32_t fr_hash_update(void const *data, size_t size, uint32_t hash);
RADIUS_PACKET *fr_radius_alloc_reply(TALLOC_CTX *ctx, RADIUS_PACKET *packet);
/*
 * error - wrapper for perror
 */
void error(char *msg) {
  perror(msg);
  exit(1);
}

int server_sendto_replay(int sockfd,RADIUS_PACKET *packet)
{
   uint8_t *temp = (uint8_t*)malloc(sizeof(uint8_t));
   size_t length=1024;
   struct sockaddr sremote;
   printf("before sendto\n");
   temp[0] = PW_CODE_ACCESS_ACCEPT;
   temp[1] = 53;
   temp[2] = 0;
   temp[3] = 20;
   printf("sendto\n");
   int sentto_client_udp = sendto(sockfd,temp,length,0,&sremote,sizeof(struct sockaddr_in));
   if (sentto_client_udp<0)
   {
      printf("Error in sendto(server_sendto_replay)\n");
      return -1;
   }
   return 0;
}


int validate_packet_radius(int data_len)
{
   if (data_len < MIN_LEN_RFC2865) //by RFC 2865 the packet most be bigger then length = 20
      {
         printf("Error - RADIUS packet is too short, the min must to be bigger then 20\n");
         return -1;
      }
   if(data_len > MAX_LEN_RFC2865) //by RFC 2865 the packet can be maximum 4096 
      {
         printf("Error - RADIUS packet is too long, the packet can be bigger then 4096\n");
         return -1;
      }
   return 0;
}

int fr_ipaddr_from_sockaddr(struct sockaddr_storage const *sa, socklen_t salen, fr_ipaddr_t *ipaddr, uint16_t *port)
{
  memset(ipaddr, 0, sizeof(*ipaddr));
  if (sa->ss_family == AF_INET) {
    struct sockaddr_in  s4;
    if (salen < sizeof(s4)) {
      printf("IPv4 address is too small");
      return 0;
    }
    memcpy(&s4, sa, sizeof(s4));
    ipaddr->af = AF_INET;
    ipaddr->prefix = 32;
    ipaddr->ipaddr.ip4addr = s4.sin_addr;
   


  } else {
    printf("Unsupported address famility %d\n",
           sa->ss_family);
    return 0;
  }

  return 1;
}
/** Read a UDP packet
 *
 * @param[in] sockfd we're reading from.
 * @param[out] data pointer where data will be written
 * @param[in] data_len length of data to read
 * @param[in] flags for things
 * @param[out] src_ipaddr of the packet.
 * @param[out] src_port of the packet.
 * @param[out] dst_ipaddr of the packet.
 * @param[out] dst_port of the packet.
 * @param[out] if_index of the interface that received the packet.
 * @param[out] when the packet was received.
 * @return
 *  - > 0 on success (number of bytes read).
 *  - < 0 on failure.
 */
ssize_t udp_recv(int sockfd, void *data, size_t data_len, int flags,
                 fr_ipaddr_t *src_ipaddr, uint16_t *src_port,
                 fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port, int *if_index,
                 struct timeval *when)
{
  int     sock_flags = 0;
  struct sockaddr_storage src;
  struct sockaddr_storage dst;
  socklen_t   sizeof_src = sizeof(src);
  socklen_t   sizeof_dst = sizeof(dst);
  ssize_t     received;
  uint16_t    port;

  if ((flags & UDP_FLAGS_PEEK) != 0)
  { 
    printf("Enter to if ((flags & UDP_FLAGS_PEEK) != 0)\n");
    sock_flags |= MSG_PEEK;
  }

  /*
   *  Connected sockets already know src/dst IP/port
   */
  if ((flags & UDP_FLAGS_CONNECTED) != 0) 
  {
      printf("Connected sockets already know src/dst IP/port\n");
      return recv(sockfd, data, data_len, sock_flags);
  }
  if (when) {
    when->tv_sec = 0;
    when->tv_usec = 0;
  }

  /*
   *  Receive the packet.  The OS will discard any data in the
   *  packet after "len" bytes.
   */
#ifdef WITH_UDPFROMTO
  if (dst_ipaddr) 
  {
    printf("WITH_UDPFROMTO - dst_ipaddr\n");
    received = recvfromto(sockfd, data, data_len, sock_flags,
              (struct sockaddr *)&src, &sizeof_src,
              (struct sockaddr *)&dst, &sizeof_dst,
              if_index, when);
  } 
  else 
  {
    printf("WITH_UDPFROMTO - (else)dst_ipaddr\n");
    received = recvfrom(sockfd, data, data_len, sock_flags,
            (struct sockaddr *)&src, &sizeof_src);
  }
#else
  {
    printf("WITH_UDPFROMTO - NOT dst_ipaddr\n");
    received = recvfrom(sockfd, data, data_len, sock_flags,(struct sockaddr *)&src, &sizeof_src);
  }
  /*
   *  Get the destination address, if requested.
   */
  if (dst_ipaddr && (getsockname(sockfd, (struct sockaddr *)&dst, &sizeof_dst) < 0)) return -1;

  if (if_index) *if_index = 0;
#endif

  if (received < 0) return received;

  if (!fr_ipaddr_from_sockaddr(&src, sizeof_src, src_ipaddr, &port)) return -1;
  *src_port = 1811;

  if (when && !when->tv_sec) gettimeofday(when, NULL); //get time of day

  if (dst_ipaddr) {
    fr_ipaddr_from_sockaddr(&dst, sizeof_dst, dst_ipaddr, &port);
    *dst_port = port;
  }

  return received;
}

void fr_isaac(fr_randctx *ctx)
{
   register uint32_t a,b,x,y,*m,*mm,*m2,*r,*mend;
   mm=ctx->randmem; r=ctx->randrsl;
   a = ctx->randa; b = (ctx->randb + (++ctx->randc)) & 0xffffffff;
   for (m = mm, mend = m2 = m+(RANDSIZ/2); m<mend; )
   {
      rngstep( a<<13, a, b, mm, m, m2, r, x);
      rngstep( a>>6 , a, b, mm, m, m2, r, x);
      rngstep( a<<2 , a, b, mm, m, m2, r, x);
      rngstep( a>>16, a, b, mm, m, m2, r, x);
   }
   for (m2 = mm; m2<mend; )
   {
      rngstep( a<<13, a, b, mm, m, m2, r, x);
      rngstep( a>>6 , a, b, mm, m, m2, r, x);
      rngstep( a<<2 , a, b, mm, m, m2, r, x);
      rngstep( a>>16, a, b, mm, m, m2, r, x);
   }
   ctx->randb = b; ctx->randa = a;
}

void fr_randinit(fr_randctx *ctx, int flag)
{
  int i;
  uint32_t a,b,c,d,e,f,g,h;
  uint32_t *m,*r;
  ctx->randa = ctx->randb = ctx->randc = 0;
  m=ctx->randmem;
  r=ctx->randrsl;
  a=b=c=d=e=f=g=h=0x9e3779b9;  /* the golden ratio */

  for (i=0; i<4; ++i) { /* scramble it */
    mix(a,b,c,d,e,f,g,h);
  }

  if (flag) {
    /* initialize using the contents of r[] as the seed */
    for (i=0; i<RANDSIZ; i+=8) {
      a+=r[i  ]; b+=r[i+1]; c+=r[i+2]; d+=r[i+3];
      e+=r[i+4]; f+=r[i+5]; g+=r[i+6]; h+=r[i+7];
      mix(a,b,c,d,e,f,g,h);
      m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
      m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
    }
     /* do a second pass to make all of the seed affect all of m */
    for (i=0; i<RANDSIZ; i+=8) {
      a+=m[i  ]; b+=m[i+1]; c+=m[i+2]; d+=m[i+3];
      e+=m[i+4]; f+=m[i+5]; g+=m[i+6]; h+=m[i+7];
      mix(a,b,c,d,e,f,g,h);
      m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
      m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
    }
  } else {
    for (i=0; i<RANDSIZ; i+=8) {
      /* fill in mm[] with messy stuff */
      mix(a,b,c,d,e,f,g,h);
      m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
      m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
    }
  }

  fr_isaac(ctx);       /* fill in the first set of results */
  ctx->randcnt=RANDSIZ;  /* prepare to use the first set of results */
}
uint32_t fr_rand(void)
{
  uint32_t num;

  /*
   *  Ensure that the pool is initialized.
   */
  if (!fr_rand_initialized) {
    fr_rand_seed(NULL, 0);
  }

  num = fr_rand_pool.randrsl[fr_rand_pool.randcnt++];
  if (fr_rand_pool.randcnt >= 256) {
    fr_rand_pool.randcnt = 0;
    fr_isaac(&fr_rand_pool);
  }

  return num;
}


 /** Return a 32-bit random number
 *
 */
 /** Seed the random number generator
 *
 * May be called any number of times.
 */
void fr_rand_seed(void const *data, size_t size)
{
  uint32_t hash;

  /*
   *  Ensure that the pool is initialized.
   */
  if (!fr_rand_initialized) {
    int fd;

    memset(&fr_rand_pool, 0, sizeof(fr_rand_pool));

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
      size_t total;
      ssize_t this;

      total = 0;
      while (total < sizeof(fr_rand_pool.randrsl)) {
        this = read(fd, fr_rand_pool.randrsl,
              sizeof(fr_rand_pool.randrsl) - total);
        if ((this < 0) && (errno != EINTR)) break;
        if (this > 0) total += this;
      }
      close(fd);
    } else {
      fr_rand_pool.randrsl[0] = fd;
      fr_rand_pool.randrsl[1] = time(NULL);
      fr_rand_pool.randrsl[2] = errno;
    }

    fr_randinit(&fr_rand_pool, 1);
    fr_rand_pool.randcnt = 0;
    fr_rand_initialized = 1;
  }

  if (!data) return;

  /*
   *  Hash the user data
   */
  hash = fr_rand();
  if (!hash) hash = fr_rand();
  hash = fr_hash_update(data, size, hash);

  fr_rand_pool.randmem[fr_rand_pool.randcnt] ^= hash;
}


uint32_t fr_hash_update(void const *data, size_t size, uint32_t hash)
{
  uint8_t const *p = data;
  uint8_t const *q = p + size;

  while (p != q) {
    hash *= FNV_MAGIC_PRIME;
    hash ^= (uint32_t) (*p++);
    }

    return hash;

}


/** Allocate a new RADIUS_PACKET
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *  the packet is not associated with a REQUEST.
 * @param new_vector if true a new request authenticator will be generated.
 * @return
 *  - New RADIUS_PACKET.
 *  - NULL on error.
 */



RADIUS_PACKET *fr_radius_alloc(TALLOC_CTX *ctx, bool new_vector)
{
  RADIUS_PACKET *rp;

  rp = talloc_zero(ctx, RADIUS_PACKET);
  if (!rp) {
    printf("out of memory");
    return NULL;
  }
  rp->id = -1;
  rp->offset = -1;

  if (new_vector) {
    int i;
    uint32_t hash, base;

    /*
     *  Don't expose the actual contents of the random
     *  pool.
     */
    base = fr_rand();
    for (i = 0; i < AUTH_VECTOR_LEN; i += sizeof(uint32_t)) {
      hash = fr_rand() ^ base;
      memcpy(rp->vector + i, &hash, sizeof(hash));
    }
  }
  fr_rand();    /* stir the pool again */

  return rp;
}

slist_t* slist = NULL;
int main(int argc, char **argv) {
   printf("RADIUS SERVER START\n----------------------\n");
   int sockfd; /* socket */
   int portno = 1811; /* port to listen on */
   struct sockaddr_in serveraddr; /* server's addr */
   uint8_t buf[BUFSIZE]; /* message buf */
   int optval; /* flag value for setsockopt */
   memset(buf,'\0',BUFSIZE);
   memset((char *) &serveraddr,0,sizeof(serveraddr));
   /* 
      * socket: create the parent socket 
   */
   sockfd = socket(AF_INET, SOCK_DGRAM, 0);
   if (sockfd < 0) 
      error("ERROR opening socket");
   if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&(int){ 1 },sizeof(int)) < 0)
   {
      error("setsockopt");
   }
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
      
   printf("Open connection to bind for new user connection\n");
   if (bind(sockfd, (struct sockaddr *) &serveraddr,sizeof(serveraddr)) < 0) 
      error("ERROR on binding");

  
  fd_set readset,writeset;
  printf("Initial List For New Connection\n");
  slist = (slist_t*)calloc(1,sizeof(slist_t));
  if (slist == NULL)
  {
    perror("Error to calloc slist requests");
  }
  slist_init(slist);
  // printf("Init TALLOC_CTX\n");
  TALLOC_CTX *ctx = NULL;
  /* 
    * main loop: wait for a datagram, then echo it
  */
    fr_ipaddr_t *src_ipaddr = (fr_ipaddr_t*)malloc(sizeof(fr_ipaddr_t));
    uint16_t *src_port =NULL;
    int nbytes;
    printf("Ready For Requests\n");
    printf("-----------------------------------------\n");
    while (1) {
      FD_ZERO(&readset);
      FD_SET(sockfd,&readset);
      
        /*
            need to allocate new request data strcutre
        */
      RADIUS_PACKET *packet = fr_radius_alloc(ctx,false);

      if (packet == NULL)
      {
        printf("error with create packer (leak in memory)\n");
        return 1;
      }
      packet->cli_len = sizeof(packet->cli);
      bzero(buf, BUFSIZE);
      if (FD_ISSET(sockfd,&readset))
      {
        memset(packet->buf, '\0',BUFSIZE);
        /*
            * recvfrom: receive a UDP datagram from a client
        */
        packet->data_len = recvfrom(sockfd, packet->buf, BUFSIZE, 0, (struct sockaddr *) &packet->cli,&packet->cli_len);
        if (packet->data_len  < 0)
           perror("ERROR in recvfrom");
        memcpy(buf,packet->buf,BUFSIZE);
        slist_append(slist,packet);
        printf("recvfrom DONE!\n");
      }

      



      printf("Start to recvived datagram !\n");
      packet->src_port = htons((unsigned short)portno);
      
      if (!fr_ipaddr_from_sockaddr(&packet->cli, packet->cli_len, src_ipaddr, src_port)) {
        printf("Unknown address family");
        return -1;
      }

      if (packet->data_len < 4) {

        return 0;
      }
      int packet_len = (buf[2] * 256) + buf[3];
      if (validate_packet_radius(packet_len) ==-1)
      {
         perror("validate_packet_radius");
         break;
      }
      
      packet->data = talloc_array(packet, uint8_t, packet_len);
      packet->data_len = packet_len;
      if (!packet->data) return -1;

        /*
         *  Double-check that the fields we want are filled in.
        */
        if ((packet->src_ipaddr.af == AF_UNSPEC) ||
            (packet->src_port == 0) ||
            (packet->dst_ipaddr.af == AF_UNSPEC) ||
            (packet->dst_port == 0)) {
          printf("Error receiving packet: %d", (errno));
          //fr_radius_free(&packet);
          return -1;
        }
      /*
         * need to check again the rfc limitiation because now packet->data_len = received
      */
      if (validate_packet_radius(packet_len) ==-1)
      {
        printf("DEBUG -- > validate_packet_radius (CP2)\n");
        free(packet);
        break;
      }

        /*
         *  Read no data.  Continue.
         *  This check is AFTER the MAX_PACKET_LEN check above, because
         *  if the packet is larger than MAX_PACKET_LEN, we also have
         *  packet->data == NULL
        */
      if ((packet->data_len == 0) || !packet->data) {
        printf("Empty packet: Socket is not ready");
        // fr_radius_free(&packet); //TODO : free function of free packet radius
        break;
      }
      
  /*
   *  Remember which socket we read the packet from.
   */
  packet->sockfd = sockfd;
  printf("----------------------------------------\n");
  // fr_radius_print_hex(packet);
  // fclose(fr_log_fp);


       //  server_sendto_replay(sockfd,packet);
      unsigned char * cat = (unsigned char *)malloc(4096);
      FD_SET(sockfd,&writeset);
      if (FD_ISSET(sockfd,&writeset))
      {
        RADIUS_PACKET *request = slist_pop_first(slist);
        //memcpy(lolo,packet,BUFSIZE);
        request->sockfd = sockfd;
        request->dst_ipaddr = packet->src_ipaddr;
        request->dst_port = packet->src_port;
        RADIUS_PACKET *replay = fr_radius_alloc_reply(ctx,request);
        if (replay == NULL)
        {
          printf("Falid with function - fr_radius_alloc_reply\n");
        }
        if (request->code == 0x01)
        {
            unsigned int len = 16;
            HMAC_CTX *ctx = HMAC_CTX_new();
           // HMAC_CTX ctx;
            HMAC_CTX_reset(&ctx);
            HMAC_Init_ex(&ctx, "test123", strlen("test123"), EVP_sha1(), NULL);
            HMAC_Update(&ctx, (unsigned char*)&request->vector, len);
            HMAC_Final(&ctx, request->vector, &len);
          request->code = 0x11;
        }
        else
        {
         // memset(cat, packet->code, 1);
          memset(cat + 1, packet, 1);
          memset(cat + 2, (char)packet, 2);
          memcpy(cat + 4, packet->vector, MD5_DIGEST_LENGTH);
          memset(cat + 4 + MD5_DIGEST_LENGTH, request, 1);
          memset(cat + 5 + MD5_DIGEST_LENGTH, request, 1);
          memcpy(cat + 6 + MD5_DIGEST_LENGTH, request, strlen(request));
          memset(cat + 6 + MD5_DIGEST_LENGTH + strlen(request), request, 1);
          memset(cat + 7 + MD5_DIGEST_LENGTH + strlen(request), request, 1);
          memcpy(cat + 8 + MD5_DIGEST_LENGTH + strlen(request), request, strlen(request));
          memcpy(cat + 8 + MD5_DIGEST_LENGTH + strlen(request) , "phone", strlen("phone"));
          memcpy(cat + 9 + MD5_DIGEST_LENGTH + strlen(request) , "test123", strlen("test123"));
          MD5(cat, 9 + MD5_DIGEST_LENGTH + strlen(request) + strlen(request) + "test123" + strlen("test123"), NULL);
          
          request->code = 0x02;
        }
       
        // HMAC_CTX_cleanup(&ctx);
        

        nbytes = sendto(sockfd,request->buf, sizeof(replay),0, (struct sockaddr *) &request->cli, sizeof(request->cli));
        if (nbytes < 0)
           perror("ERROR in sendto");
        else
           printf("sendto DONE!\n");
      }
      FD_ZERO(&writeset);
  }
  return 0;
}

void fr_radius_print_hex(RADIUS_PACKET const *packet)
{
  int i;
  fr_log_fp = fopen("file.txt","w+");
  if (!packet->data || !fr_log_fp) return;

  fprintf(fr_log_fp, "  Socket:\t%d\n", packet->sockfd); //V
#ifdef WITH_TCP
  fprintf(fr_log_fp, "  Proto:\t%d\n", packet->proto); //V
#endif

  if (packet->src_ipaddr.af == AF_INET) {
    char buffer[INET6_ADDRSTRLEN];

    fprintf(fr_log_fp, "  Src IP:\t%s\n",
      inet_ntop(packet->src_ipaddr.af,
          &packet->src_ipaddr.ipaddr,
          buffer, sizeof(buffer)));
    fprintf(fr_log_fp, "    port:\t%u\n", packet->src_port);

    fprintf(fr_log_fp, "  Dst IP:\t%s\n",
      inet_ntop(packet->dst_ipaddr.af,
          &packet->dst_ipaddr.ipaddr,
          buffer, sizeof(buffer)));
    fprintf(fr_log_fp, "    port:\t%u\n", packet->dst_port);
  }

  if (packet->data[0] < FR_MAX_PACKET_CODE) {
    fprintf(fr_log_fp, "  Code:\t\t(%d) %s\n", packet->data[0], fr_packet_codes[packet->data[0]]);
  } else {
    fprintf(fr_log_fp, "  Code:\t\t%u\n", packet->data[0]);
  }
  fprintf(fr_log_fp, "  Id:\t\t%u\n", packet->data[1]);
  fprintf(fr_log_fp, "  Length:\t%u\n", ((packet->data[2] << 8) |
           (packet->data[3])));
  fprintf(fr_log_fp, "  Vector:\t");
  for (i = 4; i < 20; i++) {
    fprintf(fr_log_fp, "%02x", packet->data[i]);
  }
  fprintf(fr_log_fp, "\n");

  if (packet->data_len > 20) {
    int total;
    uint8_t const *ptr;
    fprintf(fr_log_fp, "  Data:");

    total = packet->data_len - 20;
    ptr = packet->data + 20;

    while (total > 0) {
      int attrlen;
      unsigned int vendor = 0;

      fprintf(fr_log_fp, "\t\t");
      if (total < 2) { /* too short */
        fprintf(fr_log_fp, "%02x\n", *ptr);
        break;
      }

      if (ptr[1] > total) { /* too long */
        for (i = 0; i < total; i++) {
          fprintf(fr_log_fp, "%02x ", ptr[i]);
        }
        break;
      }

      fprintf(fr_log_fp, "%02x  %02x  ", ptr[0], ptr[1]);
      attrlen = ptr[1] - 2;

      if ((ptr[0] == PW_VENDOR_SPECIFIC) &&
          (attrlen > 4)) {
        vendor = (ptr[3] << 16) | (ptr[4] << 8) | ptr[5];
        fprintf(fr_log_fp, "%02x%02x%02x%02x (%u)  ",
               ptr[2], ptr[3], ptr[4], ptr[5], vendor);
        attrlen -= 4;
        ptr += 6;
        total -= 6;

      } else {
        ptr += 2;
        total -= 2;
      }

      print_hex_data(ptr, attrlen, 3);

      ptr += attrlen;
      total -= attrlen;
    }
  }
  fflush(stdout);
}

bool fr_radius_ok(RADIUS_PACKET *packet, bool require_ma, decode_fail_t *reason)
{
  uint8_t     *attr;
  size_t      totallen;
  int     count;
  radius_packet_t   *hdr;
  char      host_ipaddr[INET6_ADDRSTRLEN];
  bool      seen_ma = false;
  uint32_t    num_attributes;
  decode_fail_t   failure = DECODE_FAIL_NONE;

  /*
   *  Check for packets smaller than the packet header.
   *
   *  RFC 2865, Section 3., subsection 'length' says:
   *
   *  "The minimum length is 20 ..."
   */
  if (packet->data_len < RADIUS_HDR_LEN) {
    printf("Malformed RADIUS packet from host %s: too short (received %zu < minimum %d)",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)),
             packet->data_len, RADIUS_HDR_LEN);
    failure = DECODE_FAIL_MIN_LENGTH_PACKET;
    goto finish;
  }


  /*
   *  Check for packets with mismatched size.
   *  i.e. We've received 128 bytes, and the packet header
   *  says it's 256 bytes long.
   */
  totallen = (packet->data[2] << 8) | packet->data[3];
  hdr = (radius_packet_t *)packet->data;

  /*
   *  Code of 0 is not understood.
   *  Code of 16 or greate is not understood.
   */
  if ((hdr->code == 0) ||
      (hdr->code >= FR_MAX_PACKET_CODE)) {
    printf("Bad RADIUS packet from host %s: unknown packet code %d",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)),
         hdr->code);
    failure = DECODE_FAIL_UNKNOWN_PACKET_CODE;
    goto finish;
  }

  /*
   *  Message-Authenticator is required in Status-Server
   *  packets, otherwise they can be trivially forged.
   */
  if (hdr->code == PW_CODE_STATUS_SERVER) require_ma = true;

  /*
   *  Repeat the length checks.  This time, instead of
   *  looking at the data we received, look at the value
   *  of the 'length' field inside of the packet.
   *
   *  Check for packets smaller than the packet header.
   *
   *  RFC 2865, Section 3., subsection 'length' says:
   *
   *  "The minimum length is 20 ..."
   */
  if (totallen < RADIUS_HDR_LEN) {
    printf("Malformed RADIUS packet from host %s: too short (length %zu < minimum %d)",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)),
             totallen, RADIUS_HDR_LEN);
    failure = DECODE_FAIL_MIN_LENGTH_FIELD;
    goto finish;
  }

  /*
   *  And again, for the value of the 'length' field.
   *
   *  RFC 2865, Section 3., subsection 'length' says:
   *
   *  " ... and maximum length is 4096."
   *
   *  HOWEVER.  This requirement is for the network layer.
   *  If the code gets here, we assume that a well-formed
   *  packet is an OK packet.
   *
   *  We allow both the UDP data length, and the RADIUS
   *  "length" field to contain up to 64K of data.
   */

  /*
   *  RFC 2865, Section 3., subsection 'length' says:
   *
   *  "If the packet is shorter than the Length field
   *  indicates, it MUST be silently discarded."
   *
   *  i.e. No response to the NAS.
   */
  if (packet->data_len < totallen) {
    printf("Malformed RADIUS packet from host %s: received %zu octets, packet length says %zu",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)),
             packet->data_len, totallen);
    failure = DECODE_FAIL_MIN_LENGTH_MISMATCH;
    goto finish;
  }

  /*
   *  RFC 2865, Section 3., subsection 'length' says:
   *
   *  "Octets outside the range of the Length field MUST be
   *  treated as padding and ignored on reception."
   */
  if (packet->data_len > totallen) {
    /*
     *  We're shortening the packet below, but just
     *  to be paranoid, zero out the extra data.
     */
    memset(packet->data + totallen, 0, packet->data_len - totallen);
    packet->data_len = totallen;
  }

  /*
   *  Walk through the packet's attributes, ensuring that
   *  they add up EXACTLY to the size of the packet.
   *
   *  If they don't, then the attributes either under-fill
   *  or over-fill the packet.  Any parsing of the packet
   *  is impossible, and will result in unknown side effects.
   *
   *  This would ONLY happen with buggy RADIUS implementations,
   *  or with an intentional attack.  Either way, we do NOT want
   *  to be vulnerable to this problem.
   */
  attr = hdr->data;
  count = totallen - RADIUS_HDR_LEN;
  num_attributes = 0;

  while (count > 0) {
    /*
     *  We need at least 2 bytes to check the
     *  attribute header.
     */
    if (count < 2) {
      printf("Malformed RADIUS packet from host %s: attribute header overflows the packet",
           inet_ntop(packet->src_ipaddr.af,
               &packet->src_ipaddr.ipaddr,
               host_ipaddr, sizeof(host_ipaddr)));
      failure = DECODE_FAIL_HEADER_OVERFLOW;
      goto finish;
    }

    /*
     *  Attribute number zero is NOT defined.
     */
    if (attr[0] == 0) {
      printf("Malformed RADIUS packet from host %s: Invalid attribute 0",
           inet_ntop(packet->src_ipaddr.af,
               &packet->src_ipaddr.ipaddr,
               host_ipaddr, sizeof(host_ipaddr)));
      failure = DECODE_FAIL_INVALID_ATTRIBUTE;
      goto finish;
    }

    /*
     *  Attributes are at LEAST as long as the ID & length
     *  fields.  Anything shorter is an invalid attribute.
     */
    if (attr[1] < 2) {
      printf("Malformed RADIUS packet from host %s: attribute %u too short",
           inet_ntop(packet->src_ipaddr.af,
               &packet->src_ipaddr.ipaddr,
               host_ipaddr, sizeof(host_ipaddr)),
           attr[0]);
      failure = DECODE_FAIL_ATTRIBUTE_TOO_SHORT;
      goto finish;
    }

    /*
     *  If there are fewer bytes in the packet than in the
     *  attribute, it's a bad packet.
     */
    if (count < attr[1]) {
      printf("Malformed RADIUS packet from host %s: attribute %u data overflows the packet",
           inet_ntop(packet->src_ipaddr.af,
               &packet->src_ipaddr.ipaddr,
               host_ipaddr, sizeof(host_ipaddr)),
             attr[0]);
      failure = DECODE_FAIL_ATTRIBUTE_OVERFLOW;
      goto finish;
    }

    /*
     *  Sanity check the attributes for length.
     */
    switch (attr[0]) {
    default:  /* don't do anything by default */
      break;

      /*
       *  Track this for prioritizing ongoing EAP sessions.
       */
    case PW_STATE:
      if (attr[1] > 2) packet->rounds = attr[2];
      break;

      /*
       *  If there's an EAP-Message, we require
       *  a Message-Authenticator.
       */
    case PW_EAP_MESSAGE:
      require_ma = true;
      break;

    case PW_MESSAGE_AUTHENTICATOR:
      if (attr[1] != 2 + AUTH_VECTOR_LEN) {
        printf("Malformed RADIUS packet from host %s: Message-Authenticator has invalid length %d",
             inet_ntop(packet->src_ipaddr.af,
                 &packet->src_ipaddr.ipaddr,
                 host_ipaddr, sizeof(host_ipaddr)),
             attr[1] - 2);
        failure = DECODE_FAIL_MA_INVALID_LENGTH;
        goto finish;
      }
      seen_ma = true;
      break;
    }

    /*
     *  FIXME: Look up the base 255 attributes in the
     *  dictionary, and switch over their type.  For
     *  integer/date/ip, the attribute length SHOULD
     *  be 6.
     */
    count -= attr[1]; /* grab the attribute length */
    attr += attr[1];
    num_attributes++; /* seen one more attribute */
  }

  /*
   *  If the attributes add up to a packet, it's allowed.
   *
   *  If not, we complain, and throw the packet away.
   */
  if (count != 0) {
    printf("Malformed RADIUS packet from host %s: packet attributes do NOT exactly fill the packet",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)));
    failure = DECODE_FAIL_ATTRIBUTE_UNDERFLOW;
    goto finish;
  }

  /*
   *  If we're configured to look for a maximum number of
   *  attributes, and we've seen more than that maximum,
   *  then throw the packet away, as a possible DoS.
   */
  if ((fr_max_attributes > 0) &&
      (num_attributes > fr_max_attributes)) {
    printf("Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)),
         num_attributes, fr_max_attributes);
    failure = DECODE_FAIL_TOO_MANY_ATTRIBUTES;
    goto finish;
  }

  /*
   *  http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
   *
   *  A packet with an EAP-Message attribute MUST also have
   *  a Message-Authenticator attribute.
   *
   *  A Message-Authenticator all by itself is OK, though.
   *
   *  Similarly, Status-Server packets MUST contain
   *  Message-Authenticator attributes.
   */
  if (require_ma && !seen_ma) {
    printf("Insecure packet from host %s:  Packet does not contain required Message-Authenticator attribute",
         inet_ntop(packet->src_ipaddr.af,
             &packet->src_ipaddr.ipaddr,
             host_ipaddr, sizeof(host_ipaddr)));
    failure = DECODE_FAIL_MA_MISSING;
    goto finish;
  }

  /*
   *  Fill RADIUS header fields
   */
  packet->code = hdr->code;
  packet->id = hdr->id;
  memcpy(packet->vector, hdr->vector, AUTH_VECTOR_LEN);


  finish:

  if (reason) {
    *reason = failure;
  }
  return (failure == DECODE_FAIL_NONE);
}


static void print_hex_data(uint8_t const *ptr, int attrlen, int depth)
{
  int i;
  static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

  for (i = 0; i < attrlen; i++) {
    if ((i > 0) && ((i & 0x0f) == 0x00))
      fprintf(fr_log_fp, "%.*s", depth, tabs);
    fprintf(fr_log_fp, "%02x ", ptr[i]);
    if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
  }
  if ((i & 0x0f) != 0) fprintf(fr_log_fp, "\n");
}

int sendfromto(int fd, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t from_len, struct sockaddr *to, socklen_t to_len, int if_index)
{
  struct msghdr msgh;
  struct iovec  iov;
  char    cbuf[256];

  /*
   *  Unknown address family, die.
   */
  if (from && (from->sa_family != AF_INET) && (from->sa_family != AF_INET6)) {
    errno = EINVAL;
    return -1;
  }

#ifdef __FreeBSD__
  /*
   *  FreeBSD is extra pedantic about the use of IP_SENDSRCADDR,
   *  and sendmsg will fail with EINVAL if IP_SENDSRCADDR is used
   *  with a socket which is bound to something other than
   *  INADDR_ANY
   */
  struct sockaddr bound;
  socklen_t bound_len = sizeof(bound);

  if (getsockname(fd, &bound, &bound_len) < 0) {
    return -1;
  }

  switch (bound.sa_family) {
  case AF_INET:
    if (((struct sockaddr_in *) &bound)->sin_addr.s_addr != INADDR_ANY) {
      from = NULL;
    }
    break;

  case AF_INET6:
    if (!IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *) &bound)->sin6_addr)) {
      from = NULL;
    }
    break;
  }
#endif  /* !__FreeBSD__ */

  /*
   *  If the sendmsg() flags aren't defined, fall back to
   *  using sendto().  These flags are defined on FreeBSD,
   *  but laying it out this way simplifies the look of the
   *  code.
   */
#  if !defined(IP_PKTINFO) && !defined(IP_SENDSRCADDR)
  if (from && from->sa_family == AF_INET) from = NULL;
#  endif

#  if !defined(IPV6_PKTINFO)
  if (from && from->sa_family == AF_INET6) from = NULL;
#  endif

  /*
   *  No "from", just use regular sendto.
   */
  if (!from || (from_len == 0)) return sendto(fd, buf, len, flags, to, to_len);

  /* Set up control buffer iov and msgh structures. */
  memset(&cbuf, 0, sizeof(cbuf));
  memset(&msgh, 0, sizeof(msgh));
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = len;

  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_name = to;
  msgh.msg_namelen = to_len;

# if defined(IP_PKTINFO) || defined(IP_SENDSRCADDR)
  if (from->sa_family == AF_INET) {
    struct sockaddr_in *s4 = (struct sockaddr_in *) from;

#  ifdef IP_PKTINFO
    struct cmsghdr *cmsg;
    struct in_pktinfo *pkt;

    msgh.msg_control = cbuf;
    msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

    cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

    pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
    memset(pkt, 0, sizeof(*pkt));
    pkt->ipi_spec_dst = s4->sin_addr;
    pkt->ipi_ifindex = if_index;
#  endif

#  ifdef IP_SENDSRCADDR
    struct cmsghdr *cmsg;
    struct in_addr *in;

    msgh.msg_control = cbuf;
    msgh.msg_controllen = CMSG_SPACE(sizeof(*in));

    cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_SENDSRCADDR;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*in));

    in = (struct in_addr *) CMSG_DATA(cmsg);
    *in = s4->sin_addr;
#  endif
  }
#endif



  return sendmsg(fd, &msgh, flags);
}

/** Send a packet via a UDP socket.
 *
 * @param[in] sockfd we're reading from.
 * @param[in] data pointer to data to send
 * @param[in] data_len length of data to send
 * @param[in] flags to pass to send(), or sendto()
 * @param[in] src_ipaddr of the packet.
 * @param[in] src_port of the packet.
 * @param[in] if_index of the packet.
 * @param[in] dst_ipaddr of the packet.
 * @param[in] dst_port of the packet.
 */
ssize_t udp_send(int sockfd, void *data, size_t data_len, int flags,
     UDP_UNUSED fr_ipaddr_t *src_ipaddr, UDP_UNUSED uint16_t src_port, UDP_UNUSED int if_index,
     fr_ipaddr_t *dst_ipaddr, uint16_t dst_port)
{
  int rcode;

  if (flags & UDP_FLAGS_CONNECTED) {
    rcode = send(sockfd, data, data_len, 0);

  } else {
    struct sockaddr_storage dst;
    socklen_t   sizeof_dst;

    /*
     *  @fixme: We shoul probably just move to sockaddr_storage for
     *  all IP address things.
     */
    if (fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &dst, &sizeof_dst)!=1) {
      return -1;
    }


      printf("rcode with NO UDPFROMTO\n");
      rcode = sendto(sockfd, data, data_len, 0,(struct sockaddr *) &dst, sizeof_dst);
  }

  if (rcode < 0) {
    printf("udp_sendto failed : %i\n",errno);
  }

  printf("sendto code is -- > %d\n",rcode);
  return rcode;
}

int fr_ipaddr_to_sockaddr(fr_ipaddr_t const *ipaddr, uint16_t port, struct sockaddr_storage *sa, socklen_t *salen)
{
  memset(sa, 0, sizeof(*sa));

  if (ipaddr->af == AF_INET) {
    struct sockaddr_in s4;
    printf("The AF_INET is IPv4\n");
    *salen = sizeof(s4);

    memset(&s4, 0, sizeof(s4));
    s4.sin_family = AF_INET;
    s4.sin_addr = ipaddr->ipaddr.ip4addr;
    s4.sin_port = htons(port);
    memset(sa, 0, sizeof(*sa));
    memcpy(sa, &s4, sizeof(s4));

  } 
  else {
    return 0;
  }
  printf("fr_ipaddr_to_sockaddr completed! return to udp_send\n");
  return 1;
}


RADIUS_PACKET *fr_radius_alloc_reply(TALLOC_CTX *ctx, RADIUS_PACKET *packet)
{
  RADIUS_PACKET *reply;

  if (!packet) return NULL;

  reply = fr_radius_alloc(ctx, false);
  if (!reply) return NULL;

  /*
   *  Initialize the fields from the request.
   */
  reply->sockfd = packet->sockfd;
  reply->dst_ipaddr = packet->src_ipaddr;
  reply->src_ipaddr = packet->dst_ipaddr;
  reply->dst_port = packet->src_port;
  reply->src_port = packet->dst_port;
  reply->if_index = packet->if_index;
  reply->id = packet->id;
  reply->code = 0x02; /* UNKNOWN code */
  //memcpy(reply->vector, packet->vector, sizeof(reply->vector));
  reply->vps = NULL;
  reply->data = 0;
  reply->data_len = 0;

  return reply;
}
