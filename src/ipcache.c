/* $Id$ */

/*
 * DEBUG: Section 14          ipcache: IP Cache
 */

#include "squid.h"

#define MAX_LINELEN (4096)

#define MAX_IP		 1024	/* Maximum cached IP */
#define IP_LOW_WATER       70
#define IP_HIGH_WATER      90
#define MAX_HOST_NAME	  256
#define IP_INBUF_SZ	 4096

struct _ip_pending {
    int fd;
    IPH handler;
    void *handlerData;
    struct _ip_pending *next;
};

#define DNS_FLAG_ALIVE		0x01
#define DNS_FLAG_BUSY		0x02
#define DNS_FLAG_CLOSING	0x04

typedef struct _dnsserver {
    int id;
    int flags;
    int inpipe;
    int outpipe;
    time_t lastcall;
    time_t answer;
    unsigned int offset;
    unsigned int size;
    char *ip_inbuf;
    struct timeval dispatch_time;
    ipcache_entry *ip_entry;
} dnsserver_t;

static struct {
    int requests;
    int hits;
    int misses;
    int pendings;
    int dnsserver_requests;
    int dnsserver_replies;
    int errors;
    int avg_svc_time;
    int ghbn_calls;		/* # calls to blocking gethostbyname() */
    int dnsserver_hist[DefaultDnsChildrenMax];
} IpcacheStats;

typedef struct _line_entry {
    char *line;
    struct _line_entry *next;
} line_entry;

struct dnsQueueData {
    struct dnsQueueData *next;
    ipcache_entry *ip_entry;
};

static int ipcache_testname _PARAMS((void));
static char ipcache_status_char _PARAMS((ipcache_entry *));
static dnsserver_t *dnsGetFirstAvailable _PARAMS((void));
static int ipcacheHasPending _PARAMS((ipcache_entry *));
static int ipcache_compareLastRef _PARAMS((ipcache_entry **, ipcache_entry **));
static int ipcache_create_dnsserver _PARAMS((char *command));
static int ipcache_dnsHandleRead _PARAMS((int, dnsserver_t *));
static int ipcache_hash_entry_count _PARAMS((void));
static int ipcache_parsebuffer _PARAMS((char *buf, unsigned int offset, dnsserver_t *));
static int ipcache_purgelru _PARAMS((void));
static int ipcache_release _PARAMS((ipcache_entry *));
static ipcache_entry *ipcache_GetFirst _PARAMS((void));
static ipcache_entry *ipcache_GetNext _PARAMS((void));
static ipcache_entry *ipcache_create _PARAMS((void));
static void free_lines _PARAMS((line_entry *));
static void ipcache_add_to_hash _PARAMS((ipcache_entry *));
static void ipcache_call_pending _PARAMS((ipcache_entry *));
static void ipcache_call_pending_badname _PARAMS((int fd, IPH handler, void *));
static void ipcache_add _PARAMS((char *, ipcache_entry *, struct hostent *, int));
static ipcache_entry *dnsDequeue _PARAMS(());
static void dnsEnqueue _PARAMS((ipcache_entry *));
static void dnsDispatch _PARAMS((dnsserver_t *, ipcache_entry *));
static int ipcacheHasPending _PARAMS((ipcache_entry *));
static ipcache_entry *ipcache_get _PARAMS((char *));
static int dummy_handler _PARAMS((int, struct hostent * hp, void *));


static dnsserver_t **dns_child_table = NULL;
static struct hostent *static_result = NULL;
static int NDnsServersAlloc = 0;
static struct dnsQueueData *dnsQueueHead = NULL;
static struct dnsQueueData **dnsQueueTailP = &dnsQueueHead;

HashID ip_table = 0;
char *dns_error_message = NULL;	/* possible error message */
long ipcache_low = 180;
long ipcache_high = 200;

int ipcache_testname()
{
    wordlist *w = NULL;
    debug(14, 1, "Performing DNS Tests...\n");
    if ((w = getDnsTestnameList()) == NULL)
	return 1;
    for (; w; w = w->next) {
	IpcacheStats.ghbn_calls++;
	if (gethostbyname(w->key) != NULL)
	    return 1;
    }
    return 0;
}


/* TCP SOCKET VERSION */
int ipcache_create_dnsserver(command)
     char *command;
{
    int pid;
    u_short port;
    struct sockaddr_in S;
    static int n_dnsserver = 0;
    int cfd;
    int sfd;
    int len;
    int fd;

    cfd = comm_open(COMM_NOCLOEXEC,
	local_addr,
	0,
	"socket to dnsserver");
    if (cfd == COMM_ERROR) {
	debug(14, 0, "ipcache_create_dnsserver: Failed to create dnsserver\n");
	return -1;
    }
    len = sizeof(S);
    memset(&S, '\0', len);
    if (getsockname(cfd, (struct sockaddr *) &S, &len) < 0) {
	debug(14, 0, "ipcache_create_dnsserver: getsockname: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    port = ntohs(S.sin_port);
    debug(14, 4, "ipcache_create_dnsserver: bind to local host.\n");
    listen(cfd, 1);
    if ((pid = fork()) < 0) {
	debug(14, 0, "ipcache_create_dnsserver: fork: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    if (pid > 0) {		/* parent */
	comm_close(cfd);	/* close shared socket with child */
	/* open new socket for parent process */
	sfd = comm_open(0, local_addr, 0, NULL);	/* blocking! */
	if (sfd == COMM_ERROR)
	    return -1;
	if (comm_connect(sfd, localhost, port) == COMM_ERROR) {
	    comm_close(sfd);
	    return -1;
	}
	comm_set_fd_lifetime(sfd, -1);
	debug(14, 4, "ipcache_create_dnsserver: FD %d connected to %s #%d.\n",
	    sfd, command, n_dnsserver);
	return sfd;
    }
    /* child */

    no_suid();			/* give up extra priviliges */
    dup2(cfd, 3);
    for (fd = FD_SETSIZE; fd > 3; fd--)
	close(fd);
    execlp(command, "(dnsserver)", "-t", NULL);
    debug(14, 0, "ipcache_create_dnsserver: %s: %s\n", command, xstrerror());
    _exit(1);
    return 0;
}

/* removes the given ipcache entry */
int ipcache_release(i)
     ipcache_entry *i;
{
    ipcache_entry *result = 0;
    hash_link *table_entry = NULL;
    int k;

    debug(14, 5, "ipcache_release: ipcache_count before: %d \n",
	meta_data.ipcache_count);
    if (i == NULL)
	fatal_dump("ipcache_release: NULL ipcache_entry");
    if ((table_entry = hash_lookup(ip_table, i->name)) == NULL)
	return -1;
    result = (ipcache_entry *) table_entry;
    debug(14, 5, "HASH table count before delete: %d\n",
	ipcache_hash_entry_count());
    if (hash_remove_link(ip_table, table_entry)) {
	debug(14, 3, "ipcache_release: Can't delete '%s' from hash table %d\n",
	    i->name, ip_table);
    }
    debug(14, 5, "HASH table count after delete: %d\n",
	ipcache_hash_entry_count());
    if (result) {
	if (result->status == PENDING) {
	    debug(14, 1, "ipcache_release: Try to release entry with PENDING status. ignored.\n");
	    debug(14, 5, "ipcache_release: ipcache_count: %d \n", meta_data.ipcache_count);
	    return -1;
	}
	if (result->status == CACHED) {
	    if (result->addr_count)
		for (k = 0; k < (int) result->addr_count; k++)
		    safe_free(result->entry.h_addr_list[k]);
	    if (result->entry.h_addr_list)
		safe_free(result->entry.h_addr_list);
	    if (result->alias_count)
		for (k = 0; k < (int) result->alias_count; k++)
		    safe_free(result->entry.h_aliases[k]);
	    if (result->entry.h_aliases)
		safe_free(result->entry.h_aliases);
	    safe_free(result->entry.h_name);
	    debug(14, 5, "ipcache_release: Released IP cached record for '%s'.\n", i->name);
	}
	safe_free(result->name);
	memset(result, '\0', sizeof(ipcache_entry));
	safe_free(result);
    }
    --meta_data.ipcache_count;
    debug(14, 5, "ipcache_release: ipcache_count when return: %d \n",
	meta_data.ipcache_count);
    return meta_data.ipcache_count;
}

/* return match for given name */
static ipcache_entry *ipcache_get(name)
     char *name;
{
    hash_link *e;
    static ipcache_entry *result;

    result = NULL;
    if (ip_table) {
	if ((e = hash_lookup(ip_table, name)) != NULL)
	    result = (ipcache_entry *) e;
    }
    if (result == NULL)
	return NULL;

    if (((result->timestamp + result->ttl) < squid_curtime) &&
	(result->status != PENDING)) {	/* expired? */
	ipcache_release(result);
	return NULL;
    }
    return result;
}


/* get the first ip entry in the storage */
static ipcache_entry *ipcache_GetFirst()
{
    static hash_link *entryPtr;

    if ((!ip_table) || ((entryPtr = hash_first(ip_table)) == NULL))
	return NULL;
    return ((ipcache_entry *) entryPtr);
}


/* get the next ip entry in the storage for a given search pointer */
static ipcache_entry *ipcache_GetNext()
{
    static hash_link *entryPtr;

    if ((!ip_table) || ((entryPtr = hash_next(ip_table)) == NULL))
	return NULL;
    return ((ipcache_entry *) entryPtr);
}

static int ipcache_compareLastRef(e1, e2)
     ipcache_entry **e1, **e2;
{
    if (!e1 || !e2)
	fatal_dump(NULL);

    if ((*e1)->lastref > (*e2)->lastref)
	return (1);

    if ((*e1)->lastref < (*e2)->lastref)
	return (-1);

    return (0);
}



/* finds the LRU and deletes */
static int ipcache_purgelru()
{
    ipcache_entry *i = NULL;
    int local_ip_count = 0;
    int local_ip_notpending_count = 0;
    int removed = 0;
    int k;
    ipcache_entry **LRU_list = NULL;
    int LRU_list_count = 0;
    int LRU_cur_size = meta_data.ipcache_count;

    LRU_list = xcalloc(LRU_cur_size, sizeof(ipcache_entry *));

    for (i = ipcache_GetFirst(); i; i = ipcache_GetNext()) {
	local_ip_count++;

	if (LRU_list_count >= LRU_cur_size) {
	    /* have to realloc  */
	    LRU_cur_size += 16;
	    debug(14, 3, "ipcache_purgelru: Have to grow LRU_list to %d. This shouldn't happen.\n",
		LRU_cur_size);
	    LRU_list = xrealloc((char *) LRU_list,
		LRU_cur_size * sizeof(ipcache_entry *));
	}
	if ((i->status != PENDING) && (i->pending_head == NULL)) {
	    local_ip_notpending_count++;
	    LRU_list[LRU_list_count++] = i;
	}
    }

    debug(14, 3, "ipcache_purgelru: ipcache_count: %5d\n", meta_data.ipcache_count);
    debug(14, 3, "                  actual count : %5d\n", local_ip_count);
    debug(14, 3, "                  high W mark  : %5d\n", ipcache_high);
    debug(14, 3, "                  low  W mark  : %5d\n", ipcache_low);
    debug(14, 3, "                  not pending  : %5d\n", local_ip_notpending_count);
    debug(14, 3, "              LRU candidates   : %5d\n", LRU_list_count);

    /* sort LRU candidate list */
    qsort((char *) LRU_list,
	LRU_list_count,
	sizeof(i),
	(int (*)(const void *, const void *)) ipcache_compareLastRef);
    for (k = 0; LRU_list[k] && (meta_data.ipcache_count > ipcache_low)
	&& k < LRU_list_count;
	++k) {
	ipcache_release(LRU_list[k]);
	removed++;
    }

    debug(14, 3, "                   removed      : %5d\n", removed);
    safe_free(LRU_list);
    return (removed > 0) ? 0 : -1;
}


/* create blank ipcache_entry */
ipcache_entry *ipcache_create()
{
    static ipcache_entry *ipe;
    static ipcache_entry *new;
    debug(14, 5, "ipcache_create: when enter. ipcache_count == %d\n", meta_data.ipcache_count);

    if (meta_data.ipcache_count > ipcache_high) {
	if (ipcache_purgelru() < 0) {
	    debug(14, 1, "ipcache_create: Cannot release needed IP entry via LRU: %d > %d, removing first entry...\n", meta_data.ipcache_count, MAX_IP);
	    ipe = ipcache_GetFirst();
	    if (!ipe) {
		debug(14, 1, "ipcache_create: First entry is a null pointer ???\n");
		/* have to let it grow beyond limit here */
	    } else if (ipe && ipe->status != PENDING) {
		ipcache_release(ipe);
	    } else {
		debug(14, 1, "ipcache_create: First entry is also PENDING entry.\n");
		/* have to let it grow beyond limit here */
	    }
	}
    }
    meta_data.ipcache_count++;
    debug(14, 5, "ipcache_create: before return. ipcache_count == %d\n", meta_data.ipcache_count);
    new = xcalloc(1, sizeof(ipcache_entry));
    /* set default to 4, in case parser fail to get token $h_length from
     * dnsserver. */
    new->entry.h_length = 4;
    return new;

}

void ipcache_add_to_hash(i)
     ipcache_entry *i;
{
    if (hash_join(ip_table, (hash_link *) i)) {
	debug(14, 1, "ipcache_add_to_hash: Cannot add %s (%p) to hash table %d.\n",
	    i->name, i, ip_table);
    }
    debug(14, 5, "ipcache_add_to_hash: name <%s>\n", i->name);
    debug(14, 5, "                     ipcache_count: %d\n", meta_data.ipcache_count);
}


void ipcache_add(name, i, hp, cached)
     char *name;
     ipcache_entry *i;
     struct hostent *hp;
     int cached;
{
    int addr_count;
    int alias_count;
    int k;

    debug(14, 10, "ipcache_add: Adding name '%s' (%s).\n", name,
	cached ? "cached" : "not cached");

    i->name = xstrdup(name);
    if (cached) {

	/* count for IPs */
	addr_count = 0;
	while ((addr_count < 255) && hp->h_addr_list[addr_count])
	    ++addr_count;

	i->addr_count = addr_count;

	/* count for Alias */
	alias_count = 0;
	if (hp->h_aliases)
	    while ((alias_count < 255) && hp->h_aliases[alias_count])
		++alias_count;

	i->alias_count = alias_count;

	/* copy ip addresses information */
	i->entry.h_addr_list = xcalloc(addr_count + 1, sizeof(char *));
	for (k = 0; k < addr_count; k++) {
	    i->entry.h_addr_list[k] = xcalloc(1, hp->h_length);
	    memcpy(i->entry.h_addr_list[k], hp->h_addr_list[k], hp->h_length);
	}

	if (alias_count) {
	    /* copy aliases information */
	    i->entry.h_aliases = xcalloc(alias_count + 1, sizeof(char *));
	    for (k = 0; k < alias_count; k++) {
		i->entry.h_aliases[k] = xcalloc(1, strlen(hp->h_aliases[k]) + 1);
		strcpy(i->entry.h_aliases[k], hp->h_aliases[k]);
	    }
	}
	i->entry.h_length = hp->h_length;
	i->entry.h_name = xstrdup(hp->h_name);
	i->lastref = i->timestamp = squid_curtime;
	i->status = CACHED;
	i->ttl = DnsPositiveTtl;
    } else {
	i->lastref = i->timestamp = squid_curtime;
	i->status = NEGATIVE_CACHED;
	i->ttl = getNegativeDNSTTL();
    }
    ipcache_add_to_hash(i);
}




/* walks down the pending list, calling handlers */
void ipcache_call_pending(i)
     ipcache_entry *i;
{
    struct _ip_pending *p = NULL;
    int nhandler = 0;

    i->lastref = squid_curtime;

    while (i->pending_head != NULL) {
	p = i->pending_head;
	i->pending_head = p->next;
	if (p->handler) {
	    nhandler++;
	    p->handler(p->fd,
		(i->status == CACHED) ? &(i->entry) : NULL,
		p->handlerData);
	}
	memset(p, '\0', sizeof(struct _ip_pending));
	safe_free(p);
    }
    i->pending_head = NULL;	/* nuke list */
    debug(14, 10, "ipcache_call_pending: Called %d handlers.\n", nhandler);
}

void ipcache_call_pending_badname(fd, handler, data)
     int fd;
     IPH handler;
     void *data;
{
    debug(14, 0, "ipcache_call_pending_badname: Bad Name: Calling handler with NULL result.\n");
    handler(fd, NULL, data);
}

/* free all lines in the list */
void free_lines(line)
     line_entry *line;
{
    line_entry *tmp;

    while (line) {
	tmp = line;
	line = line->next;
	safe_free(tmp->line);
	safe_free(tmp);
    }
}

/* scan through buffer and do a conversion if possible 
 * return number of char used */
int ipcache_parsebuffer(buf, offset, dnsData)
     char *buf;
     unsigned int offset;
     dnsserver_t *dnsData;
{
    char *pos = NULL;
    char *tpos = NULL;
    char *endpos = NULL;
    char *token = NULL;
    char *tmp_ptr = NULL;
    line_entry *line_head = NULL;
    line_entry *line_tail = NULL;
    line_entry *line_cur = NULL;
    int ipcount;
    int aliascount;
    ipcache_entry *i = NULL;

    *dns_error_message = '\0';

    pos = buf;
    while (pos < (buf + offset)) {

	/* no complete record here */
	if ((endpos = strstr(pos, "$end\n")) == NULL) {
	    debug(14, 2, "ipcache_parsebuffer: DNS response incomplete.\n");
	    break;
	}
	line_head = line_tail = NULL;

	while (pos < endpos) {
	    /* add the next line to the end of the list */
	    line_cur = xcalloc(1, sizeof(line_entry));

	    if ((tpos = memchr(pos, '\n', 4096)) == NULL) {
		debug(14, 2, "ipcache_parsebuffer: DNS response incomplete.\n");
		return -1;
	    }
	    *tpos = '\0';
	    line_cur->line = xstrdup(pos);
	    debug(14, 7, "ipcache_parsebuffer: %s\n", line_cur->line);
	    *tpos = '\n';

	    if (line_tail)
		line_tail->next = line_cur;
	    if (line_head == NULL)
		line_head = line_cur;
	    line_tail = line_cur;
	    line_cur = NULL;

	    /* update pointer */
	    pos = tpos + 1;
	}
	pos = endpos + 5;	/* strlen("$end\n") */

	/* 
	 *  At this point, the line_head is a linked list with each
	 *  link node containing another line of the DNS response.
	 *  Start parsing...
	 */
	if (strstr(line_head->line, "$alive")) {
	    dnsData->answer = squid_curtime;
	    free_lines(line_head);
	    debug(14, 10, "ipcache_parsebuffer: $alive succeeded.\n");
	} else if (strstr(line_head->line, "$fail")) {
	    /*
	     *  The $fail messages look like:
	     *      $fail host\n$message msg\n$end\n
	     */
	    token = strtok(line_head->line, w_space);	/* skip first token */
	    token = strtok(NULL, w_space);

	    line_cur = line_head->next;
	    if (line_cur && !strncmp(line_cur->line, "$message", 8)) {
		strcpy(dns_error_message, line_cur->line + 8);
	    }
	    if (token == NULL) {
		debug(14, 1, "ipcache_parsebuffer: Invalid $fail for DNS table?\n");
	    } else {
		i = dnsData->ip_entry;
		i->lastref = i->timestamp = squid_curtime;
		i->ttl = getNegativeDNSTTL();
		i->status = NEGATIVE_CACHED;
		ipcache_call_pending(i);
		debug(14, 10, "ipcache_parsebuffer: $fail succeeded: %s.\n",
		    dns_error_message[0] ? dns_error_message : "why?");
	    }
	    free_lines(line_head);
	} else if (strstr(line_head->line, "$name")) {
	    tmp_ptr = line_head->line;
	    /* skip the first token */
	    token = strtok(tmp_ptr, w_space);
	    if ((token = strtok(NULL, w_space)) == NULL) {
		debug(14, 0, "ipcache_parsebuffer: Invalid OPCODE?\n");
	    } else {
		i = dnsData->ip_entry;
		if (i->status != PENDING) {
		    debug(14, 0, "ipcache_parsebuffer: DNS record already resolved.\n");
		} else {
		    i->lastref = i->timestamp = squid_curtime;
		    i->ttl = DnsPositiveTtl;
		    i->status = CACHED;

		    line_cur = line_head->next;

		    /* get $h_name */
		    if (line_cur == NULL ||
			!strstr(line_cur->line, "$h_name")) {
			debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $h_name.\n");
			/* abandon this record */
			break;
		    }
		    tmp_ptr = line_cur->line;
		    /* skip the first token */
		    token = strtok(tmp_ptr, w_space);
		    tmp_ptr = NULL;
		    token = strtok(tmp_ptr, w_space);
		    i->entry.h_name = xstrdup(token);

		    line_cur = line_cur->next;

		    /* get $h_length */
		    if (line_cur == NULL ||
			!strstr(line_cur->line, "$h_len")) {
			debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $h_len.\n");
			/* abandon this record */
			break;
		    }
		    tmp_ptr = line_cur->line;
		    /* skip the first token */
		    token = strtok(tmp_ptr, w_space);
		    tmp_ptr = NULL;
		    token = strtok(tmp_ptr, w_space);
		    i->entry.h_length = atoi(token);

		    line_cur = line_cur->next;

		    /* get $ipcount */
		    if (line_cur == NULL ||
			!strstr(line_cur->line, "$ipcount")) {
			debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $ipcount.\n");
			/* abandon this record */
			break;
		    }
		    tmp_ptr = line_cur->line;
		    /* skip the first token */
		    token = strtok(tmp_ptr, w_space);
		    tmp_ptr = NULL;
		    token = strtok(tmp_ptr, w_space);
		    i->addr_count = ipcount = atoi(token);

		    if (ipcount == 0) {
			i->entry.h_addr_list = NULL;
		    } else {
			i->entry.h_addr_list = xcalloc(ipcount, sizeof(char *));
		    }

		    /* get ip addresses */
		    {
			int k = 0;
			line_cur = line_cur->next;
			while (k < ipcount) {
			    if (line_cur == NULL) {
				debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $ipcount data.\n");
				break;
			    }
			    i->entry.h_addr_list[k] = xcalloc(1, i->entry.h_length);
			    *((unsigned long *) (void *) i->entry.h_addr_list[k]) = inet_addr(line_cur->line);
			    line_cur = line_cur->next;
			    k++;
			}
		    }

		    /* get $aliascount */
		    if (line_cur == NULL ||
			!strstr(line_cur->line, "$aliascount")) {
			debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $aliascount.\n");
			/* abandon this record */
			break;
		    }
		    tmp_ptr = line_cur->line;
		    /* skip the first token */
		    token = strtok(tmp_ptr, w_space);
		    tmp_ptr = NULL;
		    token = strtok(tmp_ptr, w_space);
		    i->alias_count = aliascount = atoi(token);

		    if (aliascount == 0) {
			i->entry.h_aliases = NULL;
		    } else {
			i->entry.h_aliases = xcalloc(aliascount, sizeof(char *));
		    }

		    /* get aliases */
		    {
			int k = 0;
			line_cur = line_cur->next;
			while (k < aliascount) {
			    if (line_cur == NULL) {
				debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $aliascount data.\n");
				break;
			    }
			    i->entry.h_aliases[k] = xstrdup(line_cur->line);
			    line_cur = line_cur->next;
			    k++;
			}
		    }
		    ipcache_call_pending(i);
		    debug(14, 10, "ipcache_parsebuffer: $name succeeded.\n");
		}
	    }
	    free_lines(line_head);
	} else {
	    free_lines(line_head);
	    debug(14, 1, "ipcache_parsebuffer: Invalid OPCODE for DNS table?\n");
	    return -1;
	}
    }
    return (int) (pos - buf);
}


int ipcache_dnsHandleRead(fd, dnsData)
     int fd;
     dnsserver_t *dnsData;
{
    int char_scanned;
    int len;
    int svc_time;
    int n;
    ipcache_entry *i = NULL;

    len = read(fd,
	dnsData->ip_inbuf + dnsData->offset,
	dnsData->size - dnsData->offset);
    debug(14, 5, "ipcache_dnsHandleRead: Result from DNS ID %d.\n",
	dnsData->id);
    if (len <= 0) {
	debug(14, dnsData->flags & DNS_FLAG_CLOSING ? 5 : 1,
	    "FD %d: Connection from DNSSERVER #%d is closed, disabling\n",
	    fd, dnsData->id + 1);
	dnsData->flags = 0;
	comm_close(fd);
	return 0;
    }
    n = ++IpcacheStats.dnsserver_replies;
    dnsData->offset += len;
    dnsData->ip_inbuf[dnsData->offset] = '\0';

    if (strstr(dnsData->ip_inbuf, "$end\n")) {
	/* end of record found */
	svc_time = tvSubMsec(dnsData->dispatch_time, current_time);
	if (n > IPCACHE_AV_FACTOR)
	    n = IPCACHE_AV_FACTOR;
	IpcacheStats.avg_svc_time
	    = (IpcacheStats.avg_svc_time * (n - 1) + svc_time) / n;
	char_scanned = ipcache_parsebuffer(dnsData->ip_inbuf,
	    dnsData->offset,
	    dnsData);
	if (char_scanned > 0) {
	    /* update buffer */
	    memcpy(dnsData->ip_inbuf,
		dnsData->ip_inbuf + char_scanned,
		dnsData->offset - char_scanned);
	    dnsData->offset -= char_scanned;
	    dnsData->ip_inbuf[dnsData->offset] = '\0';
	}
    }
    dnsData->ip_entry = NULL;
    dnsData->flags &= ~DNS_FLAG_BUSY;
    /* reschedule */
    comm_set_select_handler(dnsData->inpipe,
	COMM_SELECT_READ,
	(PF) ipcache_dnsHandleRead,
	dnsData);
    while ((i = dnsDequeue()) && (dnsData = dnsGetFirstAvailable()))
	dnsDispatch(dnsData, i);
    return 0;
}

int ipcache_nbgethostbyname(name, fd, handler, handlerData)
     char *name;
     int fd;
     IPH handler;
     void *handlerData;
{
    ipcache_entry *i = NULL;
    struct _ip_pending *pending = NULL;
    struct _ip_pending **I = NULL;
    dnsserver_t *dnsData = NULL;

    if (!handler)
	fatal_dump("ipcache_nbgethostbyname: NULL handler");

    debug(14, 4, "ipcache_nbgethostbyname: FD %d: Name '%s'.\n", fd, name);
    IpcacheStats.requests++;

    if (name == NULL || name[0] == '\0') {
	debug(14, 4, "ipcache_nbgethostbyname: Invalid name!\n");
	ipcache_call_pending_badname(fd, handler, handlerData);
	return 0;
    }
    i = ipcache_get(name);
    if (i != NULL && i->status != PENDING) {
	/* hit here */
	debug(14, 4, "ipcache_nbgethostbyname: HIT for '%s'\n", name);
	IpcacheStats.hits++;
	pending = xcalloc(1, sizeof(struct _ip_pending));
	pending->fd = fd;
	pending->handler = handler;
	pending->handlerData = handlerData;
	for (I = &(i->pending_head); *I; I = &((*I)->next));
	*I = pending;
	ipcache_call_pending(i);
	return 0;
    } else if (i != NULL) {
	debug(14, 4, "ipcache_nbgethostbyname: PENDING for '%s'\n", name);
	IpcacheStats.pendings++;
	pending = xcalloc(1, sizeof(struct _ip_pending));
	pending->fd = fd;
	pending->handler = handler;
	pending->handlerData = handlerData;
	for (I = &(i->pending_head); *I; I = &((*I)->next));
	*I = pending;
	return 0;
    } else {
	/* No entry, create the new one */
	debug(14, 5, "ipcache_nbgethostbyname: MISS for '%s'\n", name);
	IpcacheStats.misses++;
	pending = xcalloc(1, sizeof(struct _ip_pending));
	pending->fd = fd;
	pending->handler = handler;
	pending->handlerData = handlerData;
	i = ipcache_create();
	i->name = xstrdup(name);
	i->status = PENDING;
	i->pending_head = pending;
	ipcache_add_to_hash(i);
    }

    /* for HIT or PENDING, we've returned.  For MISS we continue ... */

    if ((dnsData = dnsGetFirstAvailable()))
	dnsDispatch(dnsData, i);
    else
	dnsEnqueue(i);
    return 0;
}

static void dnsEnqueue(i)
     ipcache_entry *i;
{
    struct dnsQueueData *new = xcalloc(1, sizeof(struct dnsQueueData));
    new->ip_entry = i;
    *dnsQueueTailP = new;
    dnsQueueTailP = &new->next;
}

static ipcache_entry *dnsDequeue()
{
    struct dnsQueueData *old = NULL;
    ipcache_entry *i = NULL;
    if (dnsQueueHead) {
	i = dnsQueueHead->ip_entry;
	old = dnsQueueHead;
	dnsQueueHead = dnsQueueHead->next;
	if (dnsQueueHead == NULL)
	    dnsQueueTailP = &dnsQueueHead;
	safe_free(old);
    }
    return i;
}

static dnsserver_t *dnsGetFirstAvailable()
{
    int k;
    dnsserver_t *dns = NULL;
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	if (!(dns->flags & DNS_FLAG_BUSY))
	    return dns;
    }
    return NULL;
}

static int ipcacheHasPending(i)
     ipcache_entry *i;
{
    struct _ip_pending *p = NULL;
    for (p = i->pending_head; p; p = p->next)
	if (p->handler)
	    return 1;
    return 0;
}


static void dnsDispatch(dns, i)
     dnsserver_t *dns;
     ipcache_entry *i;
{
    char *buf = NULL;
    if (!ipcacheHasPending(i)) {
	debug(14, 0, "dnsDispatch: skipping '%s' because no handler.\n",
	    i->name);
	return;
    }
    buf = xcalloc(1, 256);
    sprintf(buf, "%1.254s\n", i->name);
    dns->flags |= DNS_FLAG_BUSY;
    dns->ip_entry = i;
    comm_write(dns->outpipe,
	buf,
	strlen(buf),
	0,			/* timeout */
	NULL,			/* Handler */
	NULL);			/* Handler-data */
    debug(14, 5, "dnsDispatch: Request sent to DNS server #%d.\n",
	dns->id + 1);
    dns->dispatch_time = current_time;
    IpcacheStats.dnsserver_requests++;
    IpcacheStats.dnsserver_hist[dns->id]++;
}


void ipcacheOpenServers()
{
    int N = getDnsChildren();
    char *prg = getDnsProgram();
    int k;
    int dnssocket;
    static char fd_note_buf[FD_ASCII_NOTE_SZ];

    /* free old structures if present */
    if (dns_child_table) {
	for (k = 0; k < NDnsServersAlloc; k++) {
	    safe_free(dns_child_table[k]->ip_inbuf);
	    safe_free(dns_child_table[k]);
	}
	safe_free(dns_child_table);
    }
    dns_child_table = xcalloc(N, sizeof(dnsserver_t *));
    NDnsServersAlloc = N;
    debug(14, 1, "ipcacheOpenServers: Starting %d 'dns_server' processes\n", N);
    for (k = 0; k < N; k++) {
	dns_child_table[k] = xcalloc(1, sizeof(dnsserver_t));
	if ((dnssocket = ipcache_create_dnsserver(prg)) < 0) {
	    debug(14, 1, "ipcacheOpenServers: WARNING: Cannot run 'dnsserver' process.\n");
	    debug(14, 1, "              Fallling back to the blocking version.\n");
	    dns_child_table[k]->flags &= ~DNS_FLAG_ALIVE;
	} else {
	    dns_child_table[k]->flags |= DNS_FLAG_ALIVE;
	    dns_child_table[k]->id = k;
	    dns_child_table[k]->inpipe = dnssocket;
	    dns_child_table[k]->outpipe = dnssocket;
	    dns_child_table[k]->lastcall = squid_curtime;
	    dns_child_table[k]->size = IP_INBUF_SZ - 1;		/* spare one for \0 */
	    dns_child_table[k]->offset = 0;
	    dns_child_table[k]->ip_inbuf = xcalloc(IP_INBUF_SZ, 1);

	    /* update fd_stat */

	    sprintf(fd_note_buf, "%s #%d", prg, dns_child_table[k]->id + 1);
	    fd_note(dns_child_table[k]->inpipe, fd_note_buf);
	    commSetNonBlocking(dns_child_table[k]->inpipe);

	    /* clear unused handlers */
	    comm_set_select_handler(dns_child_table[k]->inpipe,
		COMM_SELECT_WRITE,
		0,
		0);
	    comm_set_select_handler(dns_child_table[k]->outpipe,
		COMM_SELECT_READ,
		0,
		0);

	    /* set handler for incoming result */
	    comm_set_select_handler(dns_child_table[k]->inpipe,
		COMM_SELECT_READ,
		(PF) ipcache_dnsHandleRead,
		(void *) dns_child_table[k]);
	    debug(14, 3, "ipcacheOpenServers: 'dns_server' %d started\n", k);
	}
    }
}

/* initialize the ipcache */
void ipcache_init()
{

    debug(14, 3, "Initializing IP Cache...\n");

    if (!dns_error_message)
	dns_error_message = xcalloc(1, 256);

    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));

    /* test naming lookup */
    if (!opt_dns_tests) {
	debug(14, 4, "ipcache_init: Skipping DNS name lookup tests.\n");
    } else if (!ipcache_testname()) {
	fatal("ipcache_init: DNS name lookup tests failed/");
    } else {
	debug(14, 1, "Successful DNS name lookup tests...\n");
    }

    ip_table = hash_create(urlcmp, 229);	/* small hash table */
    /* init static area */
    static_result = xcalloc(1, sizeof(struct hostent));
    static_result->h_length = 4;
    /* Need a terminating NULL address (h_addr_list[1]) */
    static_result->h_addr_list = xcalloc(2, sizeof(char *));
    static_result->h_addr_list[0] = xcalloc(1, 4);
    static_result->h_name = xcalloc(1, MAX_HOST_NAME + 1);

    ipcacheOpenServers();

    ipcache_high = (long) (((float) MAX_IP *
	    (float) IP_HIGH_WATER) / (float) 100);
    ipcache_low = (long) (((float) MAX_IP *
	    (float) IP_LOW_WATER) / (float) 100);
}

/* clean up the pending entries in dnsserver */
/* return 1 if we found the host, 0 otherwise */
int ipcache_unregister(name, fd)
     char *name;
     int fd;
{
    ipcache_entry *i = NULL;
    struct _ip_pending *p = NULL;

    if ((i = ipcache_get(name)) == NULL)
	return 0;
    if (i->status != PENDING)
	return 0;
    /* look for matched fd */
    for (p = i->pending_head; p; p = p->next) {
	if (p->fd == fd) {
	    p->handler = NULL;
	    safe_free(p->handlerData);
	    /* let ipcache_call_pending() remove from the linked list */
	    return 1;
	}
    }

    /* Can not find this ipcache_entry, weird */
    debug(14, 3, "ipcache_unregister: Failed to unregister FD %d from name: %s, can't find this FD.\n",
	fd, name);
    return 0;
}


struct hostent *ipcache_gethostbyname(name)
     char *name;
{
    ipcache_entry *result = NULL;
    unsigned int ip;
    struct hostent *s_result = NULL;

    if (!name)
	fatal_dump("ipcache_gethostbyname: NULL name");
    IpcacheStats.requests++;
    if (!(result = ipcache_get(name))) {
	/* cache miss */
	debug(14, 5, "ipcache_gethostbyname: IPcache miss for '%s'.\n", name);
	IpcacheStats.misses++;
	/* check if it's already a IP address in text form. */
	if ((ip = inet_addr(name)) != INADDR_NONE) {
	    *((unsigned long *) (void *) static_result->h_addr_list[0]) = ip;
	    strncpy(static_result->h_name, name, MAX_HOST_NAME);
	    return static_result;
	} else {
	    IpcacheStats.ghbn_calls++;
	    s_result = gethostbyname(name);
	}

	if (s_result && s_result->h_name && (s_result->h_name[0] != '\0')) {
	    /* good address, cached */
	    debug(14, 10, "ipcache_gethostbyname: DNS success: cache for '%s'.\n", name);
	    ipcache_add(name, ipcache_create(), s_result, 1);
	    result = ipcache_get(name);
	    return &(result->entry);
	} else {
	    /* bad address, negative cached */
	    debug(14, 3, "ipcache_gethostbyname: DNS failure: negative cache for '%s'.\n", name);
	    ipcache_add(name, ipcache_create(), s_result, 0);
	    return NULL;
	}

    }
    if (result->status != CACHED) {
	IpcacheStats.pendings++;
	debug(14, 5, "ipcache_gethostbyname: PENDING for '%s'\n", name);
	return NULL;
    }
    debug(14, 5, "ipcache_gethostbyname: HIT for '%s'\n", name);
    IpcacheStats.hits++;
    result->lastref = squid_curtime;
    return &result->entry;
}

struct hostent *ipcache_getcached(name, lookup_if_miss)
     char *name;
     int lookup_if_miss;
{
    ipcache_entry *result;
    unsigned int ip;

    if (!name)
	fatal_dump("ipcache_getcached: NULL name");
    IpcacheStats.requests++;
    if ((result = ipcache_get(name))) {
	if (result->status != CACHED) {
	    IpcacheStats.pendings++;
	    return NULL;
	}
	IpcacheStats.hits++;
	result->lastref = squid_curtime;
	return &result->entry;
    }
    IpcacheStats.misses++;
    /* check if it's already a IP address in text form. */
    if ((ip = inet_addr(name)) != INADDR_NONE) {
	*((unsigned long *) (void *) static_result->h_addr_list[0]) = ip;
	strncpy(static_result->h_name, name, MAX_HOST_NAME);
	return static_result;
    }
    if (lookup_if_miss)
	ipcache_nbgethostbyname(name, -1, dummy_handler, NULL);
    return NULL;
}


/* process objects list */
void stat_ipcache_get(sentry, obj)
     StoreEntry *sentry;
     cacheinfo *obj;
{
    ipcache_entry *i = NULL;
    int k;
    int ttl;
    char status;

    storeAppendPrintf(sentry, "{IP Cache Statistics:\n");
    storeAppendPrintf(sentry, "{IPcache Requests: %d}\n",
	IpcacheStats.requests);
    storeAppendPrintf(sentry, "{IPcache Hits: %d}\n",
	IpcacheStats.hits);
    storeAppendPrintf(sentry, "{IPcache Misses: %d}\n",
	IpcacheStats.misses);
    storeAppendPrintf(sentry, "{IPcache Pendings: %d}\n",
	IpcacheStats.pendings);
    storeAppendPrintf(sentry, "{dnsserver requests: %d}\n",
	IpcacheStats.dnsserver_requests);
    storeAppendPrintf(sentry, "{dnsserver replies: %d}\n",
	IpcacheStats.dnsserver_replies);
    storeAppendPrintf(sentry, "{dnsserver avg service time: %d msec}\n",
	IpcacheStats.avg_svc_time);
    storeAppendPrintf(sentry, "{number of dnsservers: %d}\n",
	getDnsChildren());
    storeAppendPrintf(sentry, "{Calls to gethostbyname(): %d\n",
	IpcacheStats.ghbn_calls);
    storeAppendPrintf(sentry, "{dnsservers use histogram:}\n");
    for (k = 0; k < getDnsChildren(); k++) {
	storeAppendPrintf(sentry, "{    dnsserver #%d: %d}\n",
	    k + 1,
	    IpcacheStats.dnsserver_hist[k]);
    }
    storeAppendPrintf(sentry, "}\n\n");
    storeAppendPrintf(sentry, "{IP Cache Contents:\n\n");

    for (i = ipcache_GetFirst(); i; i = ipcache_GetNext()) {
	ttl = (i->ttl - squid_curtime + i->lastref);
	status = ipcache_status_char(i);
	if (status == 'P')
	    ttl = 0;
	storeAppendPrintf(sentry, " {%s %c %d %d",
	    i->name, status, ttl, i->addr_count);
	for (k = 0; k < (int) i->addr_count; k++) {
	    struct in_addr addr;
	    memcpy((char *) &addr, i->entry.h_addr_list[k], i->entry.h_length);
	    storeAppendPrintf(sentry, " %s", inet_ntoa(addr));
	}
	for (k = 0; k < (int) i->alias_count; k++) {
	    storeAppendPrintf(sentry, " %s", i->entry.h_aliases[k]);
	}
	if (i->entry.h_name && strncmp(i->name, i->entry.h_name, MAX_LINELEN)) {
	    storeAppendPrintf(sentry, " %s", i->entry.h_name);
	}
	storeAppendPrintf(sentry, "}\n");
    }
    storeAppendPrintf(sentry, "}\n");
}

char ipcache_status_char(i)
     ipcache_entry *i;
{
    switch (i->status) {
    case CACHED:
	return ('C');
    case PENDING:
	return ('P');
    case NEGATIVE_CACHED:
	return ('N');
    default:
	debug(14, 1, "ipcache_status_char: unexpected IP cache status.\n");
    }
    return ('X');
}

int ipcache_hash_entry_count()
{
    ipcache_entry *i = NULL;
    int n = 0;
    for (i = ipcache_GetFirst(); i; i = ipcache_GetNext())
	n++;
    return n;
}

void ipcacheShutdownServers()
{
    dnsserver_t *dnsData = NULL;
    int k;
    static char *shutdown = "$shutdown\n";

    debug(14, 3, "ipcacheShutdownServers:\n");

    for (k = 0; k < getDnsChildren(); k++) {
	dnsData = *(dns_child_table + k);
	debug(14, 3, "ipcacheShutdownServers: sending '$shutdown' to dnsserver #%d\n", k);
	debug(14, 3, "ipcacheShutdownServers: --> FD %d\n", dnsData->outpipe);
	comm_write(dnsData->outpipe,
	    xstrdup(shutdown),
	    strlen(shutdown),
	    0,			/* timeout */
	    NULL,		/* Handler */
	    NULL);		/* Handler-data */
	dnsData->flags |= DNS_FLAG_CLOSING;
    }
}

static int dummy_handler(u1, u2, u3)
     int u1;
     struct hostent *u2;
     void *u3;
{
    return 0;
}
