/*
 * $Id$
 *
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

typedef enum {
    ACL_NONE,
    ACL_SRC_IP,
    ACL_DST_IP,
    ACL_DST_DOMAIN,
    ACL_TIME,
    ACL_URLPATH_REGEX,
    ACL_URL_REGEX,
    ACL_URL_PORT,
    ACL_USER,
    ACL_PROTO,
    ACL_METHOD
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
    struct _acl_ip_data *next;
};

struct _acl_time_data {
    int weekbits;
    int start;
    int stop;
    struct _acl_time_data *next;
};

/* domain data is just a wordlist */
/* user data is just a wordlist */
/* port data is just a intlist */
/* proto data is just a intlist */
/* url_regex data is just a relist */
/* method data is just a intlist */

struct _acl {
    char name[ACL_NAME_SZ + 1];
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

extern int aclCheck _PARAMS((struct _acl_access *, struct in_addr, request_t *));
extern int aclMatchAcl _PARAMS((struct _acl * acl, struct in_addr c, request_t *));
extern void aclDestroyAccessList _PARAMS((struct _acl_access ** list));
extern void aclDestroyAcls _PARAMS((void));
extern void aclParseAccessLine _PARAMS((struct _acl_access **));
extern void aclParseAclLine _PARAMS((void));
extern struct _acl *aclFindByName _PARAMS((char *name));

extern struct _acl_access *HTTPAccessList;
extern struct _acl_access *ICPAccessList;
#if DELAY_HACK
extern struct _acl_access *DelayAccessList;
#endif
