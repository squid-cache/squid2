
#if USE_ARP_ACL

/*
 * From:    dale@server.ctam.bitmcnit.bryansk.su (Dale)
 * To:      wessels@nlanr.net
 * Subject: Another Squid patch... :)
 * Date:    Thu, 04 Dec 1997 19:55:01 +0300
 * ============================================================================
 * 
 * Working on setting up a proper firewall for a network containing some
 * Win'95 computers at our Univ, I've discovered that some smart students
 * avoid the restrictions easily just changing their IP addresses in Win'95
 * Contol Panel... It has been getting boring, so I took Squid-1.1.18
 * sources and added a new acl type for hard-wired access control:
 * 
 * acl <name> arp <Ethernet address> ...
 * 
 * For example,
 * 
 * acl students arp 00:00:21:55:ed:22 00:00:21:ff:55:38
 */


#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/if_ether.h>



/*
 * Decode an ascii representation (asc) of an ethernet adress, and place
 * it in eth[6].
 */
int
decode_eth(const char *asc, char *eth)
{
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;
    if (sscanf(asc, "%x:%x:%x:%x:%x:%x", &a1, &a2, &a3, &a4, &a5, &a6) != 6) {
	debug(28, 0, "decode_eth: Invalid ethernet address '%s'\n", asc);
	return 0;		/* This is not valid address */
    }
    eth[0] = (u_char) a1;
    eth[1] = (u_char) a2;
    eth[2] = (u_char) a3;
    eth[3] = (u_char) a4;
    eth[4] = (u_char) a5;
    eth[5] = (u_char) a6;
    return 1;
}

struct _acl_arp_data *
aclParseArpData(const char *t)
{
    LOCAL_ARRAY(char, eth, 256);	/* addr1 ---> eth */
    struct _acl_arp_data *q = xcalloc(1, sizeof(struct _acl_arp_data));
    debug(28, 5, "aclParseArpData: %s\n", t);
    if (sscanf(t, "%[0-9a-f:]", eth) != 1) {
	debug(28, 0, "aclParseArpData: Bad ethernet address: '%s'\n", t);
	safe_free(q);
	return NULL;
    }
    if (!decode_eth(eth, q->eth)) {
	debug(28, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(28, 0, "aclParseArpData: Ignoring invalid ARP acl entry: can't parse '%s'\n", q);
	safe_free(q);
	return NULL;
    }
    return q;
}


/*******************/
/* aclParseArpList */
/*******************/
#if defined(USE_SPLAY_TREE)
void
aclParseArpList(void *curlist)
{
    char *t = NULL;
    splayNode **Top = curlist;
    struct _acl_arp_data *q = NULL;
    while ((t = strtokFile())) {
	if ((q = aclParseArpData(t)) == NULL)
	    continue;
	*Top = splay_insert(q, *Top, aclArpNetworkCompare);
    }
}
#elif defined(USE_BIN_TREE)
void
aclParseArpList(void **curtree)
{
    tree **Tree;
    char *t = NULL;
    struct _acl_arp_data *q;
    Tree = xmalloc(sizeof(tree *));
    *curtree = Tree;
    tree_init(Tree);
    while ((t = strtokFile())) {
	if ((q = aclParseArpData(t)) == NULL)
	    continue;
	tree_add(Tree, bintreeNetworkCompare, q, NULL);
    }
}
#else
void
aclParseArpList(void *curlist)
{
    char *t = NULL;
    struct _acl_arp_data **Tail;
    struct _acl_arp_data *q = NULL;
    for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
    while ((t = strtokFile())) {
	if ((q = aclParseArpData(t)) == NULL)
	    continue;
	*(Tail) = q;
	Tail = &q->next;
    }
}
#endif /* USE_SPLAY_TREE */


/***************/
/* aclMatchArp */
/***************/
#if defined(USE_SPLAY_TREE)
int
aclMatchArp(void *dataptr, struct in_addr c)
{
    splayNode **Top = dataptr;
    *Top = splay_splay(&eth, *Top, aclArpNetworkCompare);
    debug(28, 3, "aclMatchArp: '%s' %s\n",
	inet_ntoa(c), splayLastResult ? "NOT found" : "found");
    return !splayLastResult;
}
#elif defined(USE_BIN_TREE)
int
aclMatchArp(void *dataptr, struct in_addr c)
{
    tree **data = dataptr;
    if (tree_srch(data, bintreeArpNetworkCompare, &c)) {
	debug(28, 3, "aclMatchArp: '%s' found\n", inet_ntoa(c));
	return 1;
    }
    debug(28, 3, "aclMatchArp: '%s' NOT found\n", inet_ntoa(c));
    return 0;
}
#else
int
aclMatchArp(void *dataptr, struct in_addr c)
{
    struct _acl_arp_data **D = dataptr;
    struct _acl_arp_data *data = *D;
    struct _acl_arp_data *first, *prev;
    first = data;		/* remember first element, will never be moved */
    prev = NULL;		/* previous element in the list */
    while (data) {
	debug(28, 3, "aclMatchArp: ip    = %s\n", inet_ntoa(c));
	debug(28, 3, "aclMatchArp: arp   = %x:%x:%x:%x:%x:%x\n",
	    data->eth[0], data->eth[1], data->eth[2], data->eth[3],
	    data->eth[4], data->eth[5]);
	if (checkARP(c.s_addr, data->eth)) {
	    debug(28, 3, "aclMatchArp: returning 1\n");
	    if (prev != NULL) {
		/* shift the element just found to the second position
		 * in the list */
		prev->next = data->next;
		data->next = first->next;
		first->next = data;
	    }
	    return 1;
	}
	prev = data;
	data = data->next;
    }
    debug(28, 3, "aclMatchArp: returning 0\n");
    return 0;
}
#endif /* USE_SPLAY_TREE */

#if USE_BIN_TREE
int
bintreeArpNetworkCompare(void *t1, void *t2)
{
    struct in_addr addr;
    struct _acl_arp_data *data;
    xmemcpy(&addr, t1, sizeof(addr));
    data = (struct _acl_arp_data *) t2;
    return aclArpNetworkCompare(addr, data);
}
#endif


int
checkARP(u_long ip, char *eth)
{
    int mib[6] =
    {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
    size_t needed;
    char *buf, *next, *lim;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
	debug(28, 0, "Can't estimate ARP table size!");
	return 0;
    }
    if ((buf = malloc(needed)) == NULL) {
	debug(28, 0, "Can't allocate temporary ARP table!");
	return 0;
    }
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
	debug(28, 0, "Can't retrieve ARP table!");
	return 0;
    }
    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
	rtm = (struct rt_msghdr *) next;
	sin = (struct sockaddr_inarp *) (rtm + 1);
	sdl = (struct sockaddr_dl *) (sin + 1);
	if (sin->sin_addr.s_addr == ip) {
	    if (sdl->sdl_alen)
		if (!memcmp(LLADDR(sdl), eth, 6))
		    return 1;
	    return 0;
	}
    }
    return 0;
}

#endif /* USE_ARP_ACL */
