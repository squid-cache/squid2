/*
 * $Id$
 *
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#define ACL_NAME_SZ 32
#define BROWSERNAMELEN 128

typedef enum {
    ACL_NONE,
    ACL_SRC_IP,
    ACL_DST_IP,
    ACL_SRC_DOMAIN,
    ACL_DST_DOMAIN,
    ACL_TIME,
    ACL_URLPATH_REGEX,
    ACL_URL_REGEX,
    ACL_URL_PORT,
    ACL_USER,
    ACL_PROTO,
    ACL_METHOD,
    ACL_BROWSER,
    ACL_ENUM_MAX
} squid_acl;

#define ACL_SUNDAY	0x01
#define ACL_MONDAY	0x02
#define ACL_TUESDAY	0x04
#define ACL_WEDNESDAY	0x08
#define ACL_THURSDAY	0x10
#define ACL_FRIDAY	0x20
#define ACL_SATURDAY	0x40
#define ACL_ALLWEEK	0x7F
#define ACL_WEEKDAYS	0x3E

struct _acl_ip_data {
    struct in_addr addr1;	/* if addr2 non-zero then its a range */
    struct in_addr addr2;
    struct in_addr mask;
#ifndef USE_SPLAY_TREE
    struct _acl_ip_data *next;
#endif
};

struct _acl_time_data {
    int weekbits;
    int start;
    int stop;
    struct _acl_time_data *next;
};

struct _acl_name_list {
    char name[ACL_NAME_SZ];
    struct _acl_name_list *next;
};

struct _acl_deny_info_list {
    char url[MAX_URL];
    struct _acl_name_list *acl_list;
    struct _acl_deny_info_list *next;
};

/* domain data is just a wordlist */
/* user data is just a wordlist */
/* port data is just a intlist */
/* proto data is just a intlist */
/* url_regex data is just a relist */
/* method data is just a intlist */

struct _acl {
    char name[ACL_NAME_SZ];
    squid_acl type;
    void *data;
    char *cfgline;
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
    char *cfgline;
    struct _acl_access *next;
};

typedef enum {
    ACL_LOOKUP_NONE,
    ACL_LOOKUP_NEEDED,
    ACL_LOOKUP_PENDING,
    ACL_LOOKUP_DONE
} acl_lookup_state;

struct _aclCheck_t {
    const struct _acl_access *access_list;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    request_t *request;
    char ident[ICP_IDENT_SZ];
    char browser[BROWSERNAMELEN];
    acl_lookup_state state[ACL_ENUM_MAX];
    PF *callback;
    void *callback_data;
};

extern aclCheck_t *aclChecklistCreate _PARAMS((const struct _acl_access *,
	request_t *,
	struct in_addr src,
	char *ua,
	char *id));
extern void aclNBCheck _PARAMS((aclCheck_t *, PF *, void *));
extern int aclCheckFast _PARAMS((const struct _acl_access * A, aclCheck_t *));
extern void aclChecklistFree _PARAMS((aclCheck_t *));
extern int aclMatchAcl _PARAMS((struct _acl *, aclCheck_t *));
extern void aclDestroyAccessList _PARAMS((struct _acl_access ** list));
extern void aclDestroyAcls _PARAMS((void));
extern void aclParseAccessLine _PARAMS((struct _acl_access **));
extern void aclParseAclLine _PARAMS((void));
extern struct _acl *aclFindByName _PARAMS((const char *name));
extern char *aclGetDenyInfoUrl _PARAMS((struct _acl_deny_info_list **, const char *name));
extern void aclParseDenyInfoLine _PARAMS((struct _acl_deny_info_list **));
extern void aclDestroyDenyInfoList _PARAMS((struct _acl_deny_info_list **));
extern void aclDestroyRegexList _PARAMS((struct _relist * data));
extern int aclMatchRegex _PARAMS((relist * data, const char *word));
extern void aclParseRegexList _PARAMS((void *curlist, int icase));

extern struct _acl_access *HTTPAccessList;
extern struct _acl_access *MISSAccessList;
extern struct _acl_access *ICPAccessList;
extern struct _acl_deny_info_list *DenyInfoList;
extern const char *AclMatchedName;
