#define BUFSIZE 4
#define MAX_LEN_RFC2865 4096
#define MIN_LEN_RFC2865 20
#define UDP_FLAGS_PEEK   (1 << 1)
#define UDP_FLAGS_CONNECTED  (1 << 0)
#define AUTH_VECTOR_LEN 16
#define RANDSIZL   (8)  /* I recommend 8 for crypto, 4 for simulations */
#define RANDSIZ    (1<<RANDSIZL)
#define ind(mm,x)  ((mm)[(x>>2)&(RANDSIZ-1)])
#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)
#define RADIUS_HDR_LEN 20
#define	FR_MAX_PACKET_CODE (52)
#define PW_STATE 24
#define PW_EAP_MESSAGE 79
#define PW_MESSAGE_AUTHENTICATOR 80
#define PW_VENDOR_SPECIFIC 26
#define UDP_UNUSED
#define MD5_DIGEST_LENGTH 16


#define mix(a,b,c,d,e,f,g,h) \
{ \
   a^=b<<11; d+=a; b+=c; \
   b^=c>>2;  e+=b; c+=d; \
   c^=d<<8;  f+=c; d+=e; \
   d^=e>>16; g+=d; e+=f; \
   e^=f<<10; h+=e; f+=g; \
   f^=g>>4;  a+=f; g+=h; \
   g^=h<<8;  b+=g; h+=a; \
   h^=a>>9;  c+=h; a+=b; \
}

#define rngstep(mix,a,b,mm,m,m2,r,x) \
{ \
  x = *m;  \
  a = ((a^(mix)) + *(m2++)) & 0xffffffff; \
  *(m++) = y = (ind(mm,x) + a + b) & 0xffffffff; \
  *(r++) = b = (ind(mm,y>>RANDSIZL) + x) & 0xffffffff; \
}


/** Internal data types used within libfreeradius
 *
 */
typedef enum {
	PW_TYPE_INVALID = 0,			//!< Invalid (uninitialised) attribute type.

	PW_TYPE_STRING,				//!< String of printable characters.
	PW_TYPE_OCTETS,				//!< Raw octets.

	PW_TYPE_IPV4_ADDR,			//!< 32 Bit IPv4 Address.
	PW_TYPE_IPV4_PREFIX,			//!< IPv4 Prefix.
	PW_TYPE_IPV6_ADDR,			//!< 128 Bit IPv6 Address.
	PW_TYPE_IPV6_PREFIX,			//!< IPv6 Prefix.
	PW_TYPE_IFID,				//!< Interface ID.
	PW_TYPE_COMBO_IP_ADDR,			//!< IPv4 or IPv6 address depending on length.
	PW_TYPE_COMBO_IP_PREFIX,		//!< IPv4 or IPv6 address prefix depending on length.
	PW_TYPE_ETHERNET,			//!< 48 Bit Mac-Address.

	PW_TYPE_BOOLEAN,			//!< A truth value.
	PW_TYPE_BYTE,				//!< 8 Bit unsigned integer.
	PW_TYPE_SHORT,				//!< 16 Bit unsigned integer.
	PW_TYPE_INTEGER,			//!< 32 Bit unsigned integer.
	PW_TYPE_INTEGER64,			//!< 64 Bit unsigned integer.
	PW_TYPE_SIZE,				//!< Unsigned integer capable of representing any memory
						//!< address on the local system.
	PW_TYPE_SIGNED,				//!< 32 Bit signed integer.

	PW_TYPE_TIMEVAL,			//!< Time value (struct timeval), only for config items.
	PW_TYPE_DECIMAL,			//!< Double precision floating point.
	PW_TYPE_DATE,				//!< 32 Bit Unix timestamp.

	PW_TYPE_ABINARY,			//!< Ascend binary format a packed data structure.

	PW_TYPE_TLV,				//!< Contains nested attributes.
	PW_TYPE_STRUCT,				//!< like TLV, but without T or L, and fixed-width children

	PW_TYPE_EXTENDED,			//!< Extended attribute space attribute.
	PW_TYPE_LONG_EXTENDED,			//!< Long extended attribute space attribute.

	PW_TYPE_VSA,				//!< Vendor-Specific, for RADIUS attribute 26.
	PW_TYPE_EVS,				//!< Extended attribute, vendor specific.
	PW_TYPE_VENDOR,				//!< Attribute that represents a vendor in the attribute tree.

	PW_TYPE_MAX				//!< Number of defined data types.
} PW_TYPE;

typedef struct attr_flags {
	unsigned int		is_root : 1;			//!< Is root of a dictionary.
	unsigned int 		is_unknown : 1;			//!< Attribute number or vendor is unknown.

	unsigned int		internal : 1;			//!< Internal attribute, should not be received
								//!< in protocol packets, should not be encoded.
	unsigned int		has_tag : 1;			//!< Tagged attribute.
	unsigned int		array : 1; 			//!< Pack multiples into 1 attr.
	unsigned int		has_value : 1;			//!< Has a value.

	unsigned int		concat : 1;			//!< concatenate multiple instances
	unsigned int		is_pointer : 1;			//!< data is a pointer

	unsigned int		virtual : 1;			//!< for dynamic expansion

	unsigned int		compare : 1;			//!< has a paircompare registered

	unsigned int		named : 1;			//!< compare attributes by name.

	enum {
		FLAG_ENCRYPT_NONE = 0,				//!< Don't encrypt the attribute.
		FLAG_ENCRYPT_USER_PASSWORD,			//!< Encrypt attribute RFC 2865 style.
		FLAG_ENCRYPT_TUNNEL_PASSWORD,			//!< Encrypt attribute RFC 2868 style.
		FLAG_ENCRYPT_ASCEND_SECRET,			//!< Encrypt attribute ascend style.
		FLAG_ENCRYPT_OTHER,				//!< Non-RADIUS encryption
	} encrypt;

	uint8_t			length;				//!< length of the attribute
	uint8_t			type_size;			//!< For TLV2 and root attributes.
} fr_dict_attr_flags_t;

typedef enum fr_token {
	T_INVALID = 0,			/* invalid token */
	T_EOL,				/* end of line */
	T_LCBRACE,			/* { */
	T_RCBRACE,			/* } */
	T_LBRACE,			/* ( */
	T_RBRACE,			/* ) 		 5 */
	T_COMMA,			/* , */
	T_SEMICOLON,			/* ; */

	T_OP_INCRM,			/* ++ */
	T_OP_ADD,			/* += */
	T_OP_SUB,			/* -=  		10 */
	T_OP_SET,			/* := */
	T_OP_EQ,			/* = */
	T_OP_NE,			/* != */
	T_OP_GE,			/* >= */
	T_OP_GT,			/* > 		15 */
	T_OP_LE,			/* <= */
	T_OP_LT,			/* < */
	T_OP_REG_EQ,			/* =~ */
	T_OP_REG_NE,			/* !~ */
	T_OP_CMP_TRUE,			/* =* 		20 */
	T_OP_CMP_FALSE,			/* !* */
	T_OP_CMP_EQ,			/* == */
	T_HASH,				/* # */
	T_BARE_WORD,			/* bare word */
	T_DOUBLE_QUOTED_STRING,		/* "foo" 	25 */
	T_SINGLE_QUOTED_STRING,		/* 'foo' */
	T_BACK_QUOTED_STRING,		/* `foo` */
	T_TOKEN_LAST
} FR_TOKEN;

typedef enum value_type {
	VT_NONE = 0,						//!< VALUE_PAIR has no value.
	VT_SET,							//!< VALUE_PAIR has children.
	VT_LIST,						//!< VALUE_PAIR has multiple values.
	VT_DATA,						//!< VALUE_PAIR has a single value.
	VT_XLAT							//!< valuepair value must be xlat expanded when it's
								//!< added to VALUE_PAIR tree.
} value_type_t;

typedef struct dict_attr fr_dict_attr_t;
typedef struct value_box value_box_t;
struct value_box {
	union {
		char const	        *strvalue;		//!< Pointer to UTF-8 string.
		uint8_t const		*octets;		//!< Pointer to binary string.
		void			*ptr;			//!< generic pointer.

		struct in_addr		ipaddr;			//!< IPv4 Address.
		uint8_t			ipv4prefix[6];		//!< IPv4 prefix (should be struct?).
		struct in6_addr		ipv6addr;		//!< IPv6 Address.
		uint8_t			ipv6prefix[18];		//!< IPv6 prefix (should be struct?).
		uint8_t			ifid[8];		//!< IPv6 interface ID (should be struct?).
		uint8_t			ether[6];		//!< Ethernet (MAC) address.

		bool			boolean;		//!< A truth value.

		struct {
			union {
				uint8_t			byte;		//!< 8bit unsigned integer.
				uint16_t		ushort;		//!< 16bit unsigned integer.
				uint32_t		integer;	//!< 32bit unsigned integer.
				uint64_t		integer64;	//!< 64bit unsigned integer.
				size_t			size;		//!< System specific file/memory size.

				int32_t			sinteger;	//!< 32bit signed integer.
			};
			fr_dict_attr_t const		*enumv;		//!< Enumeration values for integer type.
		};

		struct timeval		timeval;		//!< A time value with usec precision.
		double			decimal;		//!< Double precision float.
		uint32_t		date;			//!< Date (32bit Unix timestamp).

		uint8_t			filter[32];		//!< Ascend binary format a packed data structure.

	} datum;

	PW_TYPE				type;			//!< Type of this value-box.

	size_t				length;			//!< Length of value data.

	bool				tainted;		//!< i.e. did it come from an untrusted source

	value_box_t			*next;			//!< Next in a series of value_box.
};
/* random numbers in isaac.c */
/* context of random number generator */
typedef struct fr_randctx {
	uint32_t randcnt;
	uint32_t randrsl[256];
	uint32_t randmem[256];
	uint32_t randa;
	uint32_t randb;
	uint32_t randc;
} fr_randctx;

typedef enum {
	DECODE_FAIL_NONE = 0,
	DECODE_FAIL_MIN_LENGTH_PACKET,
	DECODE_FAIL_MIN_LENGTH_FIELD,
	DECODE_FAIL_MIN_LENGTH_MISMATCH,
	DECODE_FAIL_HEADER_OVERFLOW,
	DECODE_FAIL_UNKNOWN_PACKET_CODE,
	DECODE_FAIL_INVALID_ATTRIBUTE,
	DECODE_FAIL_ATTRIBUTE_TOO_SHORT,
	DECODE_FAIL_ATTRIBUTE_OVERFLOW,
	DECODE_FAIL_MA_INVALID_LENGTH,
	DECODE_FAIL_ATTRIBUTE_UNDERFLOW,
	DECODE_FAIL_TOO_MANY_ATTRIBUTES,
	DECODE_FAIL_MA_MISSING,
	DECODE_FAIL_MAX
} decode_fail_t;

typedef struct { //TODO FIX THE NAME
	uint8_t		code;
	uint8_t		id;
	uint8_t		length[2];
	uint8_t		vector[AUTH_VECTOR_LEN];
	uint8_t		data[];
} radius_packet_t;

/** RADIUS packet codes
 *
 */
typedef enum {
	PW_CODE_UNDEFINED		= 0,	//!< Packet code has not been set
	PW_CODE_ACCESS_REQUEST		= 1,	//!< RFC2865 - Access-Request
	PW_CODE_ACCESS_ACCEPT		= 2,	//!< RFC2865 - Access-Accept
	PW_CODE_ACCESS_REJECT		= 3,	//!< RFC2865 - Access-Reject
	PW_CODE_ACCOUNTING_REQUEST	= 4,	//!< RFC2866 - Accounting-Request
	PW_CODE_ACCOUNTING_RESPONSE	= 5,	//!< RFC2866 - Accounting-Response
	PW_CODE_ACCOUNTING_STATUS	= 6,	//!< RFC3575 - Reserved
	PW_CODE_PASSWORD_REQUEST	= 7,	//!< RFC3575 - Reserved
	PW_CODE_PASSWORD_ACK		= 8,	//!< RFC3575 - Reserved
	PW_CODE_PASSWORD_REJECT		= 9,	//!< RFC3575 - Reserved
	PW_CODE_ACCOUNTING_MESSAGE	= 10,	//!< RFC3575 - Reserved
	PW_CODE_ACCESS_CHALLENGE	= 11,	//!< RFC2865 - Access-Challenge
	PW_CODE_STATUS_SERVER	 	= 12,	//!< RFC2865/RFC5997 - Status Server (request)
	PW_CODE_STATUS_CLIENT		= 13,	//!< RFC2865/RFC5997 - Status Server (response)
	PW_CODE_DISCONNECT_REQUEST	= 40,	//!< RFC3575/RFC5176 - Disconnect-Request
	PW_CODE_DISCONNECT_ACK		= 41,	//!< RFC3575/RFC5176 - Disconnect-Ack (positive)
	PW_CODE_DISCONNECT_NAK		= 42,	//!< RFC3575/RFC5176 - Disconnect-Nak (not willing to perform)
	PW_CODE_COA_REQUEST		= 43,	//!< RFC3575/RFC5176 - CoA-Request
	PW_CODE_COA_ACK			= 44,	//!< RFC3575/RFC5176 - CoA-Ack (positive)
	PW_CODE_COA_NAK			= 45,	//!< RFC3575/RFC5176 - CoA-Nak (not willing to perform)
	PW_CODE_MAX			= 255,	//!< Maximum possible code
} PW_CODE;

char const *fr_packet_codes[FR_MAX_PACKET_CODE] = {
	"",					//!< 0
	"Access-Request",
	"Access-Accept",
	"Access-Reject",
	"Accounting-Request",
	"Accounting-Response",
	"Accounting-Status",
	"Password-Request",
	"Password-Accept",
	"Password-Reject",
	"Accounting-Message",			//!< 10
	"Access-Challenge",
	"Status-Server",
	"Status-Client",
	"14",
	"15",
	"16",
	"17",
	"18",
	"19",
	"20",					//!< 20
	"Resource-Free-Request",
	"Resource-Free-Response",
	"Resource-Query-Request",
	"Resource-Query-Response",
	"Alternate-Resource-Reclaim-Request",
	"NAS-Reboot-Request",
	"NAS-Reboot-Response",
	"28",
	"Next-Passcode",
	"New-Pin",				//!< 30
	"Terminate-Session",
	"Password-Expired",
	"Event-Request",
	"Event-Response",
	"35",
	"36",
	"37",
	"38",
	"39",
	"Disconnect-Request",			//!< 40
	"Disconnect-ACK",
	"Disconnect-NAK",
	"CoA-Request",
	"CoA-ACK",
	"CoA-NAK",
	"46",
	"47",
	"48",
	"49",
	"IP-Address-Allocate",
	"IP-Address-Release",			//!< 50
};

