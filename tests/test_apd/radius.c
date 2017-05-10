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

#define ALLOC_MAGIC 0xa84ef1b2
#define FREED_MAGIC 0x67fd487a
#define TOPORT 8615
#define MYPORT 1812
#define RADIUS_DEFAULT_ATTR_COUNT 16

void * os_zalloc(size_t size);
void * os_malloc(size_t size);
void * os_memset(void *s, int c, size_t n);
void * os_memcpy(void *dest, const void *src, size_t n);

/*
 * Internal data structure for wpabuf. Please do not touch this directly from
 * elsewhere. This is only defined in header file to allow inline functions
 * from this file to access data.
 */
struct wpabuf {
  size_t size; /* total size of the allocated buffer */
  size_t used; /* length of data in the buffer */
  u8 *buf; /* pointer to the head of the buffer */
  unsigned int flags;
  /* optionally followed by the allocated buffer */
};


static void wpabuf_overflow(const struct wpabuf *buf, size_t len)
{
#ifdef WPA_TRACE
  struct wpabuf_trace *trace = wpabuf_get_trace(buf);
  if (trace->magic != WPABUF_MAGIC) {
    printf("wpabuf: invalid magic %x",
         trace->magic);
  }
#endif /* WPA_TRACE */
  printf("wpabuf %p (size=%lu used=%lu) overflow len=%lu",
       buf, (unsigned long) buf->size, (unsigned long) buf->used,
       (unsigned long) len);
  
  abort();
}


/**
 * wpabuf_len - Get the current length of a wpabuf buffer data
 * @buf: wpabuf buffer
 * Returns: Currently used length of the buffer
 */
static inline size_t wpabuf_len(const struct wpabuf *buf)
{
  return buf->used;
}


/**
 * wpabuf_mhead - Get modifiable pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline void * wpabuf_mhead(struct wpabuf *buf)
{
  return buf->buf;
}


static inline u8 * wpabuf_mhead_u8(struct wpabuf *buf)
{
  return wpabuf_mhead(buf);
}
void * wpabuf_put(struct wpabuf *buf, size_t len)
{
  void *tmp = wpabuf_mhead_u8(buf) + wpabuf_len(buf);
  buf->used += len;
  if (buf->used > buf->size) {
    wpabuf_overflow(buf, len);
  }
  return tmp;
}


static inline void wpabuf_put_data(struct wpabuf *buf, const void *data,
           size_t len)
{
  if (data)
    os_memcpy(wpabuf_put(buf, len), data, len);
}

/**
 * wpabuf_alloc - Allocate a wpabuf of the given size
 * @len: Length for the allocated buffer
 * Returns: Buffer to the allocated wpabuf or %NULL on failure
 */
struct wpabuf * wpabuf_alloc(size_t len)
{
#ifdef WPA_TRACE
  struct wpabuf_trace *trace = os_zalloc(sizeof(struct wpabuf_trace) +
                 sizeof(struct wpabuf) + len);
  struct wpabuf *buf;
  if (trace == NULL)
  {
    printf("[DEBUG] : ALLOC TRACE FALID - wpabuf_alloc\n");
    return NULL;
  }
  trace->magic = WPABUF_MAGIC;
  buf = (struct wpabuf *) (trace + 1);
#else /* WPA_TRACE */
  //struct wpabuf *buf = os_zalloc(sizeof(struct wpabuf) + len);
  struct wpabuf *buf = malloc(len*sizeof(struct wpabuf));
  //os_zalloc(sizeof(struct wpabuf) + len);
  if (buf == NULL)
  {
    printf("[DEBUG] : ALLOC BUF FALID - wpabuf_alloc\n");
    return NULL;
  }
#endif /* WPA_TRACE */

  buf->size = len;
  buf->buf = (u8 *) (buf + 1);
  return buf;
}

struct wpabuf * wpabuf_alloc_copy(const void *data, size_t len)
{
  struct wpabuf *buf = wpabuf_alloc(len);
  printf("[DEBUG] : NOT -wpabuf_alloc_copy\n");
  if (buf){
    printf("[DEBUG] : ALLOC - wpabuf_alloc_copy\n");
    wpabuf_put_data(buf, data, len);
  }
  return buf;
}

static inline void * os_calloc(size_t nmemb, size_t size)
{
  if (size && nmemb > (~(size_t) 0) / size)
    return NULL;
  return os_zalloc(nmemb * size);
}

void * os_memset(void *s, int c, size_t n)
{
  char *p = s;
  while (n--)
    *p++ = c;
  return s;
}
void * os_malloc(size_t size)
{
  return malloc(size);
}


void * os_zalloc(size_t size)
{
  void *n = os_malloc(size);
  if (n)
    os_memset(n, 0, size);
  return n;
}

void * os_memcpy(void *dest, const void *src, size_t n)
{
  char *d = dest;
  const char *s = src;
  while (n--)
    *d++ = *s++;
  return dest;
}


/**
 * struct radius_msg - RADIUS message structure for new and parsed messages
 */
struct radius_msg {
  /**
   * buf - Allocated buffer for RADIUS message
   */
  struct wpabuf *buf;

  /**
   * hdr - Pointer to the RADIUS header in buf
   */
  struct radius_hdr *hdr;

  /**
   * attr_pos - Array of indexes to attributes
   *
   * The values are number of bytes from buf to the beginning of
   * struct radius_attr_hdr.
   */
  size_t *attr_pos;

  /**
   * attr_size - Total size of the attribute pointer array
   */
  size_t attr_size;

  /**
   * attr_used - Total number of attributes in the array
   */
  size_t attr_used;
};


struct radius_hdr {
  u8 code;
  u8 identifier;
  u8 length; /* including this header */
  u8 authenticator[16];
  /* followed by length-20 octets of attributes */
} STRUCT_PACKED;

struct radius_attr_hdr {
  u8 type;
  u8 length; /* including this header */
  /* followed by length-2 octets of attribute value */
} STRUCT_PACKED_ATTR;

void radius_msg_free(struct radius_msg *msg);
static int radius_msg_add_attr_to_array(struct radius_msg *msg,struct radius_attr_hdr *attr);
struct radius_msg *msg = NULL;
struct radius_msg * radius_msg_parse(const u8 *data, size_t len);
int radius_msg_verify_msg_auth(struct radius_msg *msg, const u8 *secret,size_t secret_len, const u8 *req_auth);
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

static int radius_msg_initialize(struct radius_msg *msg)
{
  msg->attr_pos = os_calloc(RADIUS_DEFAULT_ATTR_COUNT,
          sizeof(*msg->attr_pos));
  if (msg->attr_pos == NULL)
    return -1;

  msg->attr_size = RADIUS_DEFAULT_ATTR_COUNT;
  msg->attr_used = 0;

  return 0;
}


struct dl_list {
  struct dl_list *next;
  struct dl_list *prev;
};

#define DL_LIST_HEAD_INIT(l) { &(l), &(l) }
static struct dl_list alloc_list = DL_LIST_HEAD_INIT(alloc_list);

struct os_alloc_trace {
  unsigned int magic;
  struct dl_list list;
  size_t len;

} __attribute__((aligned(16)));

struct wpa_trace_ref {
  struct dl_list list;
  const void *addr;
  // WPA_TRACE_INFO
};

static inline void dl_list_del(struct dl_list *item)
{
  item->next->prev = item->prev;
  item->prev->next = item->next;
  item->next = NULL;
  item->prev = NULL;
}




void wpa_trace_show(const char *title)
{
  struct info {
    
  } info;
  //wpa_trace_record(&info);
  //wpa_trace_dump(title, &info);
}

//#define offsetof(type, member) ((long) &((type *) 0)->member)

#define dl_list_entry(item, type, member) \
  ((type *) ((char *) item - offsetof(type, member)))

#define dl_list_for_each(item, list, type, member) \
  for (item = dl_list_entry((list)->next, type, member); \
       &item->member != (list); \
       item = dl_list_entry(item->member.next, type, member))

static struct dl_list active_references =
{ &active_references, &active_references };
void wpa_trace_check_ref(const void *addr)
{
  struct wpa_trace_ref *ref;
  dl_list_for_each(ref, &active_references, struct wpa_trace_ref, list) {
    if (addr != ref->addr)
      continue;
    //wpa_trace_show("Freeing referenced memory");
    //wpa_trace_dump("Reference registration", ref);
    abort();
  }
}

void os_free(void *ptr)
{
  struct os_alloc_trace *a;

  if (ptr == NULL)
    return;
  a = (struct os_alloc_trace *) ptr - 1;
  // if (a->magic != ALLOC_MAGIC) {
  //   printf("FREE[%p]: invalid magic 0x%x%s",
  //        a, a->magic,
  //        a->magic == FREED_MAGIC ? " (already freed)" : "");
  //   // wpa_trace_show("Invalid os_free() call");
  //   abort();
  // }
  dl_list_del(&a->list);
  a->magic = FREED_MAGIC;

  wpa_trace_check_ref(ptr);
  free(a);
}

void * os_realloc(void *ptr, size_t size)
{
  struct os_alloc_trace *a;
  size_t copy_len;
  void *n;

  if (ptr == NULL)
    return os_malloc(size);

  a = (struct os_alloc_trace *) ptr - 1;
  // if (a->magic != ALLOC_MAGIC) {
  //   printf("REALLOC[%p]: invalid magic 0x%x%s",
  //        a, a->magic,
  //        a->magic == FREED_MAGIC ? " (already freed)" : "");
  //   //wpa_trace_show("Invalid os_realloc() call");
  //   abort();
  // }
  n = os_malloc(size);
  if (n == NULL)
    return NULL;
  copy_len = a->len;
  if (copy_len > size)
    copy_len = size;
  os_memcpy(n, a + 1, copy_len);
  printf("Realloc\n");
  //os_free(ptr);
  return n;
}


static inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
  if (size && nmemb > (~(size_t) 0) / size)
  {
    printf("[DEBUG] : os_realloc_array( FALID\n");
    return NULL;
  }
  printf("[DEBUG] : os_realloc_array( DONE !\n");
  return os_realloc(ptr, nmemb * size);
}

/**
 * wpabuf_head - Get pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline const void * wpabuf_head(const struct wpabuf *buf)
{
  return buf->buf;
}

static inline const u8 * wpabuf_head_u8(const struct wpabuf *buf)
{
  return wpabuf_head(buf);
}

/**
 * wpabuf_free - Free a wpabuf
 * @buf: wpabuf buffer
 */
void wpabuf_free(struct wpabuf *buf)
{
#ifdef WPA_TRACE
  struct wpabuf_trace *trace;
  if (buf == NULL)
    return;
  trace = wpabuf_get_trace(buf);
  if (trace->magic != WPABUF_MAGIC) {
    wpa_printf(MSG_ERROR, "wpabuf_free: invalid magic %x",
         trace->magic);
    wpa_trace_show("wpabuf_free magic mismatch");
    abort();
  }
  if (buf->flags )
    os_free(buf->buf);
  printf("wpabuf_free\n");
  os_free(trace);
#else /* WPA_TRACE */
  if (buf == NULL)
  {
    printf("[DEBUG] : wpabuf FALID !\n");
    return;
  }
  if (buf->flags )
  {
    printf("[DEBUG] : buf->flags FREED\n");
    os_free(buf->buf);
  }
  printf("[DEBUG] : os_free FREED !\n");
  os_free(buf);
#endif /* WPA_TRACE */
}

static int radius_msg_add_attr_to_array(struct radius_msg *msg,
          struct radius_attr_hdr *attr)
{
  printf("[DEBUG] : radius_msg_add_attr_to_array Inside !\n");
  if (msg->attr_used >= msg->attr_size) {
    size_t *nattr_pos;
    int nlen = msg->attr_size * 2;
    printf("[DEBUG] : msg->attr_used >= msg->attr_size\n");
    nattr_pos = os_realloc_array(msg->attr_pos, nlen,
               sizeof(*msg->attr_pos));
    printf("[DEBUG] : os_realloc_array \n");
    if (nattr_pos == NULL)
      return -1;
    printf("[DEBUG] : os_realloc_array DONE ! \n");
    msg->attr_pos = nattr_pos;
    msg->attr_size = nlen;
  }

  msg->attr_pos[msg->attr_used++] = (unsigned int *) attr - wpabuf_head_u8(msg->buf);

  return 0;
}

/**
 * radius_msg_parse - Parse a RADIUS message
 * @data: RADIUS message to be parsed
 * @len: Length of data buffer in octets
 * Returns: Parsed RADIUS message or %NULL on failure
 *
 * This parses a RADIUS message and makes a copy of its data. The caller is
 * responsible for freeing the returned data with radius_msg_free().
 */
struct radius_msg * radius_msg_parse(const u8 *data, size_t len)
{
  struct radius_msg *msg;
  struct radius_hdr *hdr;
  struct radius_attr_hdr *attr;
  size_t msg_len;
  unsigned char  *pos, *end;

  if (data == NULL)
    return NULL;

  hdr = (struct radius_hdr *) data;

 
  msg = os_zalloc(sizeof(*msg));
  if (msg == NULL)
    return NULL;
  msg_len = be_to_host16(hdr->length);
  msg->buf = wpabuf_alloc_copy(data, msg_len);
  printf("[DEBUG] : wpabuf_alloc_copy DONE !\n");
  if (msg->buf == NULL || radius_msg_initialize(msg)) {
    printf("radius_msg_parse\n");
    radius_msg_free(msg);
    return NULL;
  }
  printf("[DEBUG] : radius_msg_initialize(msg) DONE !\n");
  msg->hdr = wpabuf_mhead(msg->buf);
  printf("[DEBUG] : rwpabuf_mhead(msg->buf) DONE !\n");
  /* parse attributes */
  pos = wpabuf_mhead_u8(msg->buf) + sizeof(struct radius_hdr);
  printf("[DEBUG] : pos = wpabuf_mhead_u8 DONE !\n");
  end = wpabuf_mhead_u8(msg->buf) + wpabuf_len(msg->buf);
  printf("[DEBUG] : end = wpabuf_mhead_u8 DONE !\n");
  while (pos < end) {
     if ((size_t) (end - pos) < sizeof(*attr))
       goto fail;

     attr = (struct radius_attr_hdr *) pos;
     printf("[DEBUG] : attr Inside\n");
    if (pos + attr->length > end || attr->length < sizeof(*attr))
    {
      printf("[DEBUG] : attr Inside - FALID\n");
      goto fail;
    }

    /* TODO: check that attr->length is suitable for attr->type */

    if (radius_msg_add_attr_to_array(msg, attr))
    {
      printf("[DEBUG] : radius_msg_add_attr_to_array(msg, attr) FALID !\n");
      goto fail;
    }

    pos += attr->length;
  }

  return msg;

 fail:
  radius_msg_free(msg);
  return NULL;
}
static struct radius_attr_hdr *
radius_get_attr_hdr(struct radius_msg *msg, int idx)
{
  return (struct radius_attr_hdr *)
    (wpabuf_mhead_u8(msg->buf) + msg->attr_pos[idx]);
}


static void MD5Transform(u32 buf[4], u32 const in[16]);



/* ===== start - public domain MD5 implementation ===== */
/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ifndef WORDS_BIGENDIAN
#define byteReverse(buf, len) /* Nothing */
#else
/*
 * Note: this code is harmless on little-endian machines.
 */
static void byteReverse(unsigned char *buf, unsigned longs)
{
    u32 t;
    do {
  t = (u32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
      ((unsigned) buf[1] << 8 | buf[0]);
  *(u32 *) buf = t;
  buf += 4;
    } while (--longs);
}
#endif

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len)
{
    u32 t;

    /* Update bitcount */

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((u32) len << 3)) < t)
  ctx->bits[1]++;   /* Carry from low to high */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;  /* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
  unsigned char *p = (unsigned char *) ctx->in + t;

  t = 64 - t;
  if (len < t) {
      os_memcpy(p, buf, len);
      return;
  }
  os_memcpy(p, buf, t);
  byteReverse(ctx->in, 16);
  MD5Transform(ctx->buf, (u32 *) ctx->in);
  buf += t;
  len -= t;
    }
    /* Process data in 64-byte chunks */

    while (len >= 64) {
  os_memcpy(ctx->in, buf, 64);
  byteReverse(ctx->in, 16);
  MD5Transform(ctx->buf, (u32 *) ctx->in);
  buf += 64;
  len -= 64;
    }

    /* Handle any remaining bytes of data. */

    os_memcpy(ctx->in, buf, len);
}


/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}


void * __hide_aliasing_typecast(void *foo);
#define aliasing_hide_typecast(a,t) (t *) __hide_aliasing_typecast((a))

void * __hide_aliasing_typecast(void *foo)
{
  return foo;
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5Final(unsigned char digest[16], struct MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
  /* Two lots of padding:  Pad the first block to 64 bytes */
  os_memset(p, 0, count);
  byteReverse(ctx->in, 16);
  MD5Transform(ctx->buf, (u32 *) ctx->in);

  /* Now fill the next block with 56 bytes */
  os_memset(ctx->in, 0, 56);
    } else {
  /* Pad block to 56 bytes */
  os_memset(p, 0, count - 8);
    }
    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ((u32 *) aliasing_hide_typecast(ctx->in, u32))[14] = ctx->bits[0];
    ((u32 *) aliasing_hide_typecast(ctx->in, u32))[15] = ctx->bits[1];

    MD5Transform(ctx->buf, (u32 *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    os_memcpy(digest, ctx->buf, 16);
    os_memset(ctx, 0, sizeof(*ctx));  /* In case it's sensitive */
}


/**
 * md5_vector - MD5 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
  MD5_CTX ctx;
  size_t i;

  MD5Init(&ctx);
  for (i = 0; i < num_elem; i++)
    MD5Update(&ctx, addr[i], len[i]);
  MD5Final(mac, &ctx);
  return 0;
}




/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void MD5Transform(u32 buf[4], u32 const in[16])
{
    register u32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}
/* ===== end - public domain MD5 implementation ===== */




int hmac_md5_vector(const u8 *key, size_t key_len, size_t num_elem,
        const u8 *addr[], const size_t *len, u8 *mac)
{
  u8 k_pad[64]; /* padding - key XORd with ipad/opad */
  u8 tk[16];
  const u8 *_addr[6];
  size_t i, _len[6];
  int res;

  if (num_elem > 5) {
    /*
     * Fixed limit on the number of fragments to avoid having to
     * allocate memory (which could fail).
     */
    return -1;
  }

        /* if key is longer than 64 bytes reset it to key = MD5(key) */
        if (key_len > 64) {
    if (md5_vector(1, &key, &key_len, tk))
      return -1;
    key = tk;
    key_len = 16;
        }

  /* the HMAC_MD5 transform looks like:
   *
   * MD5(K XOR opad, MD5(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected */

  /* start out by storing key in ipad */
  os_memset(k_pad, 0, sizeof(k_pad));
  os_memcpy(k_pad, key, key_len);

  /* XOR key with ipad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x36;

  /* perform inner MD5 */
  _addr[0] = k_pad;
  _len[0] = 64;
  for (i = 0; i < num_elem; i++) {
    _addr[i + 1] = addr[i];
    _len[i + 1] = len[i];
  }
  if (md5_vector(1 + num_elem, _addr, _len, mac))
    return -1;

  os_memset(k_pad, 0, sizeof(k_pad));
  os_memcpy(k_pad, key, key_len);
  /* XOR key with opad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x5c;

  /* perform outer MD5 */
  _addr[0] = k_pad;
  _len[0] = 64;
  _addr[1] = mac;
  _len[1] = MD5_MAC_LEN;
  res = md5_vector(2, _addr, _len, mac);
  os_memset(k_pad, 0, sizeof(k_pad));
  os_memset(tk, 0, sizeof(tk));
  return res;
}


/**
 * hmac_md5 - HMAC-MD5 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_md5(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
        u8 *mac)
{
  return hmac_md5_vector(key, key_len, 1, &data, &data_len, mac);
}


int os_memcmp_const(const void *a, const void *b, size_t len)
{
  const u8 *aa = a;
  const u8 *bb = b;
  size_t i;
  u8 res;

  for (res = 0, i = 0; i < len; i++)
    res |= aa[i] ^ bb[i];

  return res;
}

int radius_msg_verify_msg_auth(struct radius_msg *msg, const u8 *secret,size_t secret_len, const u8 *req_auth)
{
  u8 auth[MD5_MAC_LEN], orig[MD5_MAC_LEN];
  u8 orig_authenticator[16];
  struct radius_attr_hdr *attr = NULL, *tmp;
  size_t i;

  for (i = 0; i < msg->attr_used; i++) {
    tmp = radius_get_attr_hdr(msg, i);
    if (tmp->type == RADIUS_ATTR_MESSAGE_AUTHENTICATOR) {
      if (attr != NULL) {
        printf("Multiple Message-Authenticator attributes in RADIUS message");
        return 1;
      }
      attr = tmp;
    }
  }

  if (attr == NULL) {
    printf("No Message-Authenticator attribute found");
    return 1;
  }

  os_memcpy(orig, attr + 1, MD5_MAC_LEN);
  os_memset(attr + 1, 0, MD5_MAC_LEN);
  if (req_auth) {
    os_memcpy(orig_authenticator, msg->hdr->authenticator,
        sizeof(orig_authenticator));
    os_memcpy(msg->hdr->authenticator, req_auth,
        sizeof(msg->hdr->authenticator));
  }
  hmac_md5(secret, secret_len, wpabuf_head(msg->buf),
     wpabuf_len(msg->buf), auth);
  os_memcpy(attr + 1, orig, MD5_MAC_LEN);
  if (req_auth) {
    os_memcpy(msg->hdr->authenticator, orig_authenticator,
        sizeof(orig_authenticator));
  }

  if (os_memcmp_const(orig, auth, MD5_MAC_LEN) != 0) {
    printf("Invalid Message-Authenticator!");
    return 1;
  }

  return 0;
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
 u8 *buf = NULL;
 union {
    struct sockaddr_storage ss;
    struct sockaddr_in sin;
  } from;
 buf = os_malloc(4096);
 

 my_ip(myniccardm, myipaddressm);


 /* get the host info */
 if ((he = gethostbyname("192.168.1.103")) == NULL) {
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
 if((numbytes = recvfrom(sockfd, buf, sizeof(Packet), 0, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
      printf("ERROR: recvfrom\n");
      return EXIT_FAILURE;
    }
    printf("RECEIVED---\n");
      // printf("code:\t\t{%02x}\n", buf->code);
      // printf("identifier:\t{%02x}\n", buf->identifier);
      // printf("length:\t\t%d\n", buf->length);
      // printf("authenticator:\t");
      // print_bytes(buf->authenticator, MD5_DIGEST_LENGTH);
      // printf("-attributes-\n");
      // printf("type:\t\t{%02x}\n", buf->username.type);
      // printf("length:\t\t%d\n", (int)buf->username.length);
      // printf("value:\t\t%s\n", buf->username.value);
      // printf("type:\t\t{%02x}\n", buf->password.type);
      // printf("length:\t\t%d\n", (int)buf->password.length);
      // printf("value:\t\t");
      // print_bytes(buf->password.value, MD5_DIGEST_LENGTH);
      // printf("\n");
 /* host byte order */
 their_addr.sin_family = AF_INET;
 /* short, network byte order */
 printf("Sender: Using port: %d\n",TOPORT);
 their_addr.sin_port = htons(TOPORT);
 their_addr.sin_addr = *((struct in_addr *)he->h_addr);
 /* zero the rest of the struct */
 memset(&(their_addr.sin_zero), '\0', 8);
 
struct radius_server_data *data = eloop_ctx;
char abuf[50];
struct radius_client *client = NULL;

    client = radius_server_get_client(data, &from.sin.sin_addr, 0);

 //msg = radius_msg_parse(buf, sizeof(Packet));

if (radius_msg_verify_msg_auth(buf, (u8 *) client->shared_secret,
               client->shared_secret_len, NULL)) {
    RADIUS_DEBUG("Invalid Message-Authenticator from %s", abuf);
    data->counters.bad_authenticators++;
    client->counters.bad_authenticators++;
    goto fail;
  }






 if((numbytes = sendto(sockfd, request,sizeof(Packet),0,(struct sockaddr *)&their_addr,sizeof(struct sockaddr))) == -1) {
       perror("Sender: Client-sendto() error lol!");
       exit(1);
       }
   else
       printf("Sender: Client-sendto() is OK...\n");

}  
 return 0;

 }//main


 /**
 * radius_msg_free - Free a RADIUS message
 * @msg: RADIUS message from radius_msg_new() or radius_msg_parse()
 */
void radius_msg_free(struct radius_msg *msg)
{
  if (msg == NULL)
    return;
  printf("radius_msg_free\n");
  wpabuf_free(msg->buf);
  os_free(msg->attr_pos);
  os_free(msg);
}