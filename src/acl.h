#define ACL_NAME_SZ 32

typedef enum {
	ACL_NONE,
	ACL_SRC_IP,
	ACL_DST_DOMAIN,
	ACL_TIME,
	ACL_URL_REGEX,
	ACL_URL_PORT,
	ACL_USER,
	ACL_PROTO
} acl_t;

#define ACL_SUNDAY	0x01
#define ACL_MONDAY	0x02
#define ACL_TUESDAY	0x04
#define ACL_WEDNESDAY	0x08
#define ACL_THURSDAY	0x10
#define ACL_FRIDAY	0x20
#define ACL_SATURDAY	0x40
#define ACL_ALLWEEK	0x4F

struct _acl_ip_data {
	struct in_addr addr1;	/* if addr2 non-zero then its a range */
	struct in_addr mask1;
	struct in_addr addr2;
	struct in_addr mask2;
	struct _acl_ip_data *next;
};

struct _acl_time_data {
	int 	weekbits;
	int	start;
	int 	stop;
	struct _acl_time_data *next;
};

/* domain data is just a wordlist */
/* user data is just a wordlist */
/* port data is just a intlist */
/* proto data is just a intlist */
/* url_regex data is just a relist */

struct _acl {
	char name[ACL_NAME_SZ+1];
	acl_t type;
	void *data;
	struct _acl *next;
};

struct _acl_list {
	int op;
	struct _acl *acl;
	struct _acl_list *next;
};

struct _acl_access {
	int allow;
	struct _acl_list *acl_list;
	struct _acl_access *next;
};

extern void aclParseAclLine _PARAMS((void));
extern void aclParseAccessLine _PARAMS((void));
