#include "squid.h"
#include "snmp.h"
#include "asn1.h"
#include "snmp_vars.h"
#include "cache_snmp.h"
#include "snmp_oidlist.h"


/*
 * squid is under:   .1.3.6.1.3.25.17   ( length=7)
 */
#ifndef MIN
#define MIN(a,b) (a<b?a:b)
#endif

/**********************************************************************/

/* First, we have a huge array of MIBs this agent knows about */

/* group handler definition */

oid_ParseFn *basicGetFn(oid *, snint);
oid_ParseFn *basicGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *sysGetFn(oid *, snint);
oid_ParseFn *sysGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *sysFdGetFn(oid *, snint);
oid_ParseFn *sysFdGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *sysConnGetFn(oid *, snint);
oid_ParseFn *sysConnGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *confGetFn(oid *, snint);
oid_ParseFn *confGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *confStGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *prfSysGetFn(oid *, snint);
oid_ParseFn *prfSysGetFn(oid *, snint);
oid_ParseFn *prfSysGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *prfProtoGetFn(oid *, snint);
oid_ParseFn *prfProtoGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *netdbGetFn(oid *, snint);
oid_ParseFn *netdbGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *dnsGetFn(oid *, snint);
oid_ParseFn *dnsGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *meshGetFn(oid *, snint);
oid_ParseFn *meshPtblGetNextFn(oid *, snint, oid **, snint *);
int meshPtblGetRowFn(oid *,oid *);
int sysConnGetRowFn(oid *,oid *);
extern int meshCtblGetRowFn(oid *,oid *);
extern int netdbGetRowFn(oid *,oid *);
oid_ParseFn *meshCtblGetNextFn(oid *, snint, oid **, snint *);
oid_ParseFn *accGetFn(oid *, snint);
oid_ParseFn *accGetNextFn(oid *, snint, oid **, snint *);

oid_ParseFn *genericGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen,
    oid * MIBRoot, int MIBRootLen, oid_GetRowFn *getRowFn, int tblen, oid * MIBTail,
    oid_ParseFn * mygetFn, int MIBTailLen, int MIB_ACTION_INDEX);

struct MIBListEntry MIBList[] =
{
    {
	{SYSMIB}, LEN_SYSMIB, basicGetFn, basicGetNextFn},
    {
	{SQ_SYS}, LEN_SQ_SYS, sysGetFn, sysGetNextFn},
    {
        {SQ_SYS, 3}, LEN_SQ_SYS + 1, sysConnGetFn, sysConnGetNextFn},
    {
	{SQ_SYS, 4}, LEN_SQ_SYS + 1, sysFdGetFn, sysFdGetNextFn},
    {
	{SQ_CONF}, LEN_SQ_CONF, confGetFn, confGetNextFn},
    {
	{SQ_CONF, 6}, LEN_SQ_CONF + 1, confGetFn, confStGetNextFn},
    {
	{SQ_PRF, 1}, LEN_SQ_PRF + 1, prfSysGetFn, prfSysGetNextFn},
    {
	{SQ_PRF, 2}, LEN_SQ_PRF + 1, prfProtoGetFn, prfProtoGetNextFn},
    {
	{SQ_NET, 1}, LEN_SQ_NET + 1, netdbGetFn, netdbGetNextFn},
    {
	{SQ_NET, 2}, LEN_SQ_NET + 1, dnsGetFn, dnsGetNextFn},
    {
	{SQ_MESH, 1}, LEN_SQ_MESH + 1, meshGetFn,meshPtblGetNextFn},
    {
        {SQ_MESH, 2}, LEN_SQ_MESH + 1, meshGetFn,meshCtblGetNextFn},
    {
	{0}, 0, NULL, NULL}
};

extern int fqdn_getMax(), ipcache_getMax();
int fd_getMax();
struct in_addr * gen_getMax();

/**********************************************************************
 * General OID Functions
 **********************************************************************/
void
print_oid(oid * Name, snint Len)
{
    static char mbuf[16], objid[1024];
    int x;
    objid[0] = '\0';
    for (x = 0; x < Len; x++) {
	snprintf(mbuf, 16, ".%u", (unsigned char) Name[x]);
	strcat(objid, mbuf);
    }
    debug(49, 9) ("   oid = %s\n", objid);
}

int
oidcmp(oid * A, snint ALen, oid * B, snint BLen)
{
    oid *aptr = A;
    oid *bptr = B;
    snint m = MIN(ALen, BLen);

    /* Compare the first M bytes. */
    while (m) {
	if (*aptr < *bptr)
	    return (-1);
	if (*aptr++ > *bptr++)
	    return (1);
	m--;
    }

    /* The first M bytes were identical.  So, they share the same
     * root.  The shorter one must come first.
     */
    if (ALen < BLen)
	return (-1);

    if (ALen > BLen)
	return (1);

    /* Same length, all bytes identical.  Must be the same OID. */
    return (0);
}

int
oidncmp(oid * A, snint ALen, oid * B, snint BLen, snint CompLen)
{
    oid *aptr = A;
    oid *bptr = B;
    snint m = MIN(MIN(ALen, BLen), CompLen);
    snint count = 0;

    /* Compare the first M bytes. */
    while (count != m) {
	if (*aptr < *bptr)
	    return (-1);
	if (*aptr++ > *bptr++)
	    return (1);
	count++;
    }

    if (m == CompLen)
	return (0);


    if (ALen < BLen)
	return (-1);

    if (ALen > BLen)
	return (1);

    /* Same length, all bytes identical.  Must be the same OID. */
    return (0);
}

/* Allocate space for, and copy, an OID.  Returns new oid, or NULL.
 */
oid *
oiddup(oid * A, snint ALen)
{
    oid *Ans;

    Ans = (oid *) xmalloc(sizeof(oid) * ALen);
    if (Ans)
	memcpy(Ans, A, (sizeof(oid) * ALen));
    return (Ans);
}


/**********************************************************************
 * OIDLIST FUNCTIONS
 *
 * Find the parsing function for OIDs registered in this agent.
 **********************************************************************/

oid_ParseFn *
oidlist_Find(oid * Src, snint SrcLen)
{
    struct MIBListEntry *Ptr;
    int ret;

    debug(49, 5) ("oidlist_Find:  Called.\n ");
    print_oid(Src, SrcLen);

    for (Ptr = MIBList; Ptr->GetFn; Ptr++) {

	ret = oidncmp(Src, SrcLen, Ptr->Name, Ptr->NameLen, Ptr->NameLen);

	if (!ret) {

	    /* Cool.  We found the mib it's in.  Let it find the function.
	     */
	    debug(49, 7) ("oidlist_Find:  found, returning GetFn Ptr! \n");

	    return ((*Ptr->GetFn) (Src, SrcLen));
	}
	if (ret < 0) {
	    debug(49, 7) ("oidlist_Find:  We just passed it, so it doesn't exist.\n ");
	    /* We just passed it, so it doesn't exist. */
	    return (NULL);
	}
    }

    debug(49, 5) ("oidlist_Find:  the request was past the end.  It doesn't exist.\n");
    /* We get here if the request was past the end.  It doesn't exist. */
    return (NULL);
}
/* Find the next item.  For SNMP_PDU_GETNEXT requests. 
 *
 * Returns a pointer to the parser function, and copies the oid to dest.
 * 
 */
oid_ParseFn *
oidlist_Next(oid * Src, snint SrcLen, oid ** DestP, snint *DestLenP)
{
    struct MIBListEntry *Ptr;
    int ret;
    oid_ParseFn *Fn = NULL;

    debug(49, 6) ("oidlist_Next: Looking for next of:\n");
    print_oid(Src, SrcLen);

    for (Ptr = MIBList; Ptr->GetNextFn; Ptr++) {

	/* Only look at as much as we have stored */
	ret = oidncmp(Src, SrcLen, Ptr->Name, Ptr->NameLen, Ptr->NameLen);

	if (!ret) {
	    debug(49, 6) ("oidlist_Next: Checking MIB\n");

	    /* Cool.  We found the mib it's in.  Ask it.
	     */
	    while (Ptr != NULL && Ptr->GetNextFn) {
		Fn = ((*Ptr->GetNextFn) (Src, SrcLen, DestP, DestLenP));
		if (Fn == NULL) {
		    /* If this returned NULL, we're looking for the first
		     * in the next MIB.
		     */
		    debug(49, 6) ("oidlist_Next: Not in this entry. Trying next.\n");
		    Ptr++;
		    continue;
		}
		return Fn;
	    }
	    /* Return what we found.  NULL if it wasn't in the MIB, and there
	     * were no more MIBs. 
	     */
	    debug(49, 3) ("oidlist_Next: No next mib.\n");
	    return NULL;
	}
	if (ret < 0) {
	    /* We just passed the mib it would be in.  Return 
	     * the next in this MIB.
	     */
	    debug(49, 3) ("oidlist_Next: Passed mib.  Checking this one.\n");
	    return ((*Ptr->GetNextFn) (Src, SrcLen, DestP, DestLenP));
	}
    }

    /* We get here if the request was past the end.  It doesn't exist. */
    debug(49, 7) ("oidlist_Next: Found nothing.\n");
    return (NULL);
}



/* SQUID MIB implementation */

oid_ParseFn *
genericGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen,
    oid * MIBRoot, int MIBRootLen, oid_GetRowFn *getRowFn, int tblen, oid * MIBTail,
    oid_ParseFn * mygetFn, int MIBTailLen, int MIB_ACTION_INDEX)
{
    int ret;
    oid *Ptr;
    int i = 0;
    oid nullOid[] = { 0,0,0,0, 0};

    debug(49, 6) ("genericGetNextFn: Called with root=%d, tail=%d index=%d:\n",
	MIBRootLen, MIBTailLen, MIB_ACTION_INDEX);
    print_oid(MIBRoot, MIBRootLen);

    ret = oidcmp(Src, SrcLen, MIBRoot, MIBRootLen);
    if ((ret < 0) || (ret == 0)) {
	/* The requested OID is before this MIB.  Return the first
	 * entry.
	 */
	*DestLen = MIBTailLen;
	*Dest = (oid *) xmalloc(sizeof(oid) * (*DestLen));
	if (*Dest == NULL)
	    return (NULL);

	/* Initialize the OID to the first action */
	xmemcpy((oid *) * Dest, (oid *) MIBTail, (MIBTailLen * sizeof(oid)));

	/* Set this to action 1 */
	Ptr = *Dest;

	Ptr[MIB_ACTION_INDEX] = 1;
	if (!getRowFn)
		Ptr[MIBTailLen - 1] = 1;
	else
		if (!getRowFn(&Ptr[MIBTailLen-tblen], nullOid))
			return NULL;

	debug(49, 6) ("genericGetNextFn:  On this mib (%d).\n", MIB_ACTION_INDEX);
	return (mygetFn);
    }
    ret = oidcmp(Src, SrcLen, MIBTail, MIBTailLen);
    if (ret > 0) {
	/* Beyond us. */
	debug(49, 5) ("genericGetNextFn:  Beyond this mib.  Returning nothing.\n");
	print_oid(Src, SrcLen);
	print_oid(MIBTail, MIBTailLen);
	return (NULL);
    }
    /* Ok. Let's copy the first MIBTailLen parts of the OID.  That's
     * all this MIB really cares about.
     */
    *DestLen = MIBTailLen;

    /* Allocate space for the new OID */
    *Dest = (oid *) xmalloc(sizeof(oid) * (*DestLen));
    if (*Dest == NULL)
	return (NULL);

    /* Initialize the OID to the first action
     *
     * Incoming OID must be at least (MIBRootLen)+1 bytes.  Less would
     * have already been returned.
     */
    Ptr = *Dest;
    debug(49,9)("genericGetNextFn: SrcLen=%d , MIBTailLen=%d\n", 
		SrcLen, MIBTailLen);
    if (SrcLen <= MIBTailLen) {
	/* Copy everything we can, and fill in the blanks */
	debug(49, 5) ("genericGetNextFn: Adding missing information.\n");
	xmemcpy(Ptr, Src, (SrcLen * sizeof(oid)));

	if (SrcLen != MIBTailLen) {
	    for (i = SrcLen - 1; i < MIBTailLen; i++)
		Ptr[i] = 1;
	    if (getRowFn) 
		if (!getRowFn(&Ptr[MIBTailLen-tblen], nullOid))
                        return NULL;
	}
    } else {
	/* Src too long.  Just copy the first part. */
	xmemcpy(Ptr, Src, (MIBTailLen * sizeof(oid)));
    }

    debug(49, 5) ("genericGetNextFn:  (Probably) in this MIB.  Creating dest.\n");

    /* Look at the next item */

    if (getRowFn) {
	if (!getRowFn(&Ptr[MIBTailLen-tblen], &Ptr[MIBTailLen-tblen])) {
            debug(49, 5) ("genericGetNextFn:end of row!\n");
		/* no more rows, next action or finished. */
	    Ptr[MIB_ACTION_INDEX]++;
	    if (Ptr[MIB_ACTION_INDEX] > MIBTail[MIB_ACTION_INDEX]) {
                debug(49, 5) ("genericGetNextFn:Beyond last action! (%d)\n",
                    Ptr[MIB_ACTION_INDEX]);
                xfree(*Dest);
                return (NULL);
            }
	    assert (getRowFn(&Ptr[MIBTailLen-tblen], nullOid));
	}
    } else {

    Ptr[MIBTailLen - 1]++;

    if (Ptr[MIBTailLen - 1] > MIBTail[MIBTailLen - 1]) {
	/* Too far! */
	if (MIBTailLen > MIBRootLen + 1) {
	    Ptr[MIB_ACTION_INDEX]++;
	    Ptr[MIBTailLen - 1] = 1;
	    if (Ptr[MIB_ACTION_INDEX] > MIBTail[MIB_ACTION_INDEX]) {
		debug(49, 5) ("genericGetNextFn:Beyond last action! (%d)\n",
		    Ptr[MIB_ACTION_INDEX]);
		xfree(*Dest);
		return (NULL);
	    }
	} else {
	    debug(49, 5) ("genericGetNextFn:Beyond last entry! (%d)\n", Ptr[MIBTailLen - 1]);
	    xfree(*Dest);
	    return (NULL);
	}
    }
    }
    return (mygetFn);
}

oid_ParseFn *
basicGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("basicGetFn: here,requested:%d\n", Src[7]);
    if (((SrcLen == (LEN_SYSMIB + 1)) ||
	    ((SrcLen == (LEN_SYSMIB + 2)) && (Src[LEN_SYSMIB + 1] == 0))) &&
	(Src[LEN_SYSMIB] > 0) &&
	(Src[LEN_SYSMIB] < SYS_END))
	return (snmp_basicFn);

    return NULL;
}
oid_ParseFn *
basicGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid_ParseFn *retFn = NULL;
    oid MIBRoot[] =
    {SYSMIB};
    int MIBRootLen = LEN_SYSMIB;
    oid MIBTail[LEN_SYSMIB + 1] =
    {SYSMIB, SYS_END-1};

    retFn = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL, 1, MIBTail, snmp_basicFn,
	LEN_SYSMIB + 1, LEN_SYSMIB);

    return retFn;
}


oid_ParseFn *
sysGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("sysGetFn: here! with Src[8]=%d\n", Src[8]);
    if ((SrcLen == LEN_SQ_SYS + 4 && Src[LEN_SQ_SYS] == SYSFDTBL)||
	(SrcLen == LEN_SQ_SYS + 8 && Src[LEN_SQ_SYS] == SYSCONNTBL))
	return snmp_sysFn;
    if (SrcLen != LEN_SQ_SYS + 1)
	return NULL;
    if (Src[LEN_SQ_SYS] > 0 && Src[LEN_SQ_SYS] < 3)
	return snmp_sysFn;

    return NULL;
}

oid_ParseFn *
sysGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_SYS};
    int MIBRootLen = LEN_SQ_SYS;
    oid MIBTail[LEN_SQ_SYS + 1] =
    {SQ_SYS, 2};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL, 1, MIBTail, snmp_sysFn,
	LEN_SQ_SYS + 1, LEN_SQ_SYS);
    return ret;
}

oid_ParseFn *
sysFdGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("sysGetFn: here, requested: %d\n", Src[8]);
    if (SrcLen == LEN_SQ_SYS + 4 && Src[LEN_SQ_SYS] == SYSFDTBL)
	return snmp_sysFn;

    return NULL;
}

oid_ParseFn *
sysConnGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("sysGetFn: here, requested: %d\n", Src[8]);
    if (SrcLen == LEN_SQ_SYS + 8 && Src[LEN_SQ_SYS] == SYSCONNTBL)
        return snmp_sysFn;

    return NULL;
}

oid_ParseFn *
sysConnGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_SYS, SYSCONNTBL};
    int MIBRootLen = LEN_SQ_SYS + 1;
    oid MIBTail[LEN_SQ_SYS + 8] =
    {SQ_SYS, SYSCONNTBL, 1, SYS_CONN_END - 1, 0, 0, 0, 0, 0};
    oid_ParseFn *ret;

    addr2oid( *gen_getMax(), &MIBTail[LEN_SQ_MESH +3] );
    MIBTail[LEN_SQ_SYS + 7] = 0;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
        MIBRoot, MIBRootLen, sysConnGetRowFn , 5, MIBTail, snmp_sysFn,
        LEN_SQ_SYS + 8, LEN_SQ_SYS + 2);
    return ret;
}

oid_ParseFn *
sysFdGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_SYS, SYSFDTBL};
    int MIBRootLen = LEN_SQ_SYS + 1;
    oid MIBTail[LEN_SQ_SYS + 4] =
    {SQ_SYS, SYSFDTBL, 1, SYS_FD_END - 1, 0};
    oid_ParseFn *ret;

    MIBTail[LEN_SQ_SYS + 3] = fd_getMax();

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL , 1, MIBTail, snmp_sysFn,
	LEN_SQ_SYS + 4, LEN_SQ_SYS + 2);
    return ret;
}

oid_ParseFn *
meshGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("meshGetFn: here! with Src[8]=%d and %d\n", Src[8], SrcLen);

    if (SrcLen != LEN_SQ_MESH + 7)
        return NULL;
    switch (Src[LEN_SQ_MESH]) {
    case MESH_PTBL:
        return snmp_meshPtblFn;
    case MESH_CTBL:
        return snmp_meshCtblFn;
    }
    return NULL;
}

oid_ParseFn *
confGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("confGetFn: here! with Src[8]=%d and %d\n", Src[8], SrcLen);

    switch (Src[LEN_SQ_CONF]) {
    case CONF_STORAGE:
	if (SrcLen != LEN_SQ_CONF + 2)
	    return NULL;
	return snmp_confFn;
    default:
	if (SrcLen < LEN_SQ_CONF)
	    return NULL;
    }
    return snmp_confFn;
}
oid_ParseFn *
confGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_CONF};
    int MIBRootLen = LEN_SQ_CONF;
    oid MIBTail[LEN_SQ_CONF + 1] =
    {SQ_CONF, CONF_LOG_FAC};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL, 1, MIBTail, snmp_confFn,
	LEN_SQ_CONF + 1, LEN_SQ_CONF);
    return ret;
}

oid_ParseFn *
confStGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_CONF, CONF_STORAGE};
    int MIBRootLen = LEN_SQ_CONF + 1;
    oid MIBTail[LEN_SQ_CONF + 2] =
    {SQ_CONF, CONF_STORAGE, CONF_ST_END - 1};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL , 1, MIBTail, snmp_confFn,
	LEN_SQ_CONF + 2, LEN_SQ_CONF + 1);
    return ret;
}

int
sysConnGetRowFn(oid *New, oid *Oid)
{
	int cnt=0, act=0;
        int port=0;
	static char buf[16];
	static fde *f = NULL;
	static fde *ff = NULL;

        if (!Oid[0]&&!Oid[1]&&!Oid[2]&&!Oid[3])
		act=1;
	else {
		snprintf(buf,16, "%d.%d.%d.%d", Oid[0], Oid[1],Oid[2],Oid[3]);
		port=Oid[4];
		debug(49,9)("sysConnGetRowFn: input [%s]:%d\n", buf,port);
	}
        while (cnt < Squid_MaxFD) {
            f = &fd_table[cnt++];
            if (!f->open)
                continue;
            if (f->type==FD_SOCKET && f->remote_port!=0) {
		debug(49,9)("sysConnGetRowFn: now [%s]:%d\n", f->ipaddr,f->remote_port);
		if (ff)
		debug(49,9)("sysConnGetRowFn: prev [%s]:%d\n", ff->ipaddr,ff->remote_port);
		if (act || (ff && !strcmp(ff->ipaddr, buf )&& (port==ff->remote_port)))
			break;
	    	ff=f;
	    }
        }
	if (!f || f->type!=FD_SOCKET || !f->ipaddr) {
		debug(49,9)("sysConnGetRowFn: returning 0\n", buf);
		return 0;
	}

	debug(49,9)("sysConnGetRowFn: returning [%s]:%d\n", f->ipaddr,f->remote_port);
	sscanf(f->ipaddr, "%d.%d.%d.%d", &New[0],&New[1],&New[2],&New[3]);
	New[4]=f->remote_port;
	return 1;	
}

int 
meshPtblGetRowFn(oid *New, oid *Oid)
{
	peer *p;
	struct in_addr *maddr;
	if (!Oid[0]&&!Oid[1]&&!Oid[2]&&!Oid[3])
		p=Config.peers;
	else {
		maddr=oid2addr(Oid);
		for (p=Config.peers; p!=NULL ; p=p->next) {
			if ( p->in_addr.sin_addr.s_addr == 
				maddr->s_addr)
				break;
		}
		if (!p || !p->next) return 0;
		p=p->next;
	}
	addr2oid(p->in_addr.sin_addr, New);
	return 1;
}

oid_ParseFn *
meshPtblGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_MESH, MESH_PTBL};
    int MIBRootLen = LEN_SQ_MESH + 1;
    oid MIBTail[LEN_SQ_MESH + 7] =
    {SQ_MESH, MESH_PTBL, 1, MESH_PTBL_END - 1, 0 , 0, 0 , 0};
    int numPeers = 0;
    snint max_addr=0;
    oid_ParseFn *ret;
    /* XXX should be smarter than that */
    peer *pp= NULL;
    peer *p = Config.peers;
    while (p) {
	numPeers++;
	if (p->in_addr.sin_addr.s_addr > max_addr) {
		max_addr=p->in_addr.sin_addr.s_addr;
		pp=p;
	}
	p = p->next;
    }
    addr2oid(pp->in_addr.sin_addr , &MIBTail[LEN_SQ_MESH +3] );

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, meshPtblGetRowFn , 4, MIBTail, snmp_meshPtblFn,
	LEN_SQ_MESH + 7, LEN_SQ_MESH + 2);
    return ret;
}

oid_ParseFn *
meshCtblGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_MESH, MESH_CTBL};
    int MIBRootLen = LEN_SQ_MESH + 1;
    oid MIBTail[LEN_SQ_MESH + 7] =
    {SQ_MESH, MESH_CTBL, 1, MESH_CTBL_END - 1, 0, 0, 0 , 0};
    oid_ParseFn *ret;

    addr2oid( *gen_getMax(), &MIBTail[LEN_SQ_MESH +3] );

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
        MIBRoot, MIBRootLen, meshCtblGetRowFn , 4, MIBTail, snmp_meshCtblFn,
        LEN_SQ_MESH + 7, LEN_SQ_MESH + 2);
    return ret;
}

oid_ParseFn *
prfSysGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("prfSysGetFn: called with %d, %d, %d\n", SrcLen,
	Src[LEN_SQ_PRF + 1], LEN_SQ_PRF + 1);

    if (SrcLen != LEN_SQ_PRF + 2 || Src[LEN_SQ_PRF + 1] >= PERF_SYS_END)
	return NULL;
    return snmp_prfSysFn;
}

oid_ParseFn *
prfSysGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_PRF, PERF_SYS};
    int MIBRootLen = LEN_SQ_PRF + 1;
    oid MIBTail[LEN_SQ_PRF + 2] =
    {SQ_PRF, PERF_SYS, PERF_SYS_END - 1};

    debug(49, 5) ("prfSysGetNextFn: called.\n");

    return genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL , 1 , MIBTail, snmp_prfSysFn,
	LEN_SQ_PRF + 2, LEN_SQ_PRF + 1);

}

oid_ParseFn *
prfProtoGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("prfProtoGetFn: called with %d\n", SrcLen);

    if (Src[LEN_SQ_PRF + 1] == PERF_PROTOSTAT_MEDIAN && SrcLen == LEN_SQ_PRF + 5)
	return snmp_prfProtoFn;

    if (SrcLen != LEN_SQ_PRF + 3 || Src[LEN_SQ_PRF] >= PERF_PROTOSTAT_END)
	return NULL;
    return snmp_prfProtoFn;
}

oid_ParseFn *
prfProtoGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, 1, 0, 0};
    int MIBRootLen = LEN_SQ_PRF + 2;
    oid MIBTail[] =
    {SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_END - 1, 0, 0, 0};
    oid_ParseFn *ret;

    if (Src[LEN_SQ_PRF + 1] <= PERF_PROTOSTAT_AGGR) {
	ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	    MIBRoot, MIBRootLen, NULL , 1, MIBTail, snmp_prfProtoFn,
	    LEN_SQ_PRF + 3, LEN_SQ_PRF + 2);
	if (ret)
	    return ret;
    }
    MIBRoot[LEN_SQ_PRF + 1] = PERF_PROTOSTAT_MEDIAN;
    MIBRoot[LEN_SQ_PRF + 2] = 1;
    MIBRoot[LEN_SQ_PRF + 3] = 1;
    MIBRootLen += 1;
    MIBTail[LEN_SQ_PRF + 1] = PERF_PROTOSTAT_MEDIAN;
    MIBTail[LEN_SQ_PRF + 2] = 1;
    MIBTail[LEN_SQ_PRF + 3] = PERF_MEDIAN_END - 1;
    MIBTail[LEN_SQ_PRF + 4] = N_COUNT_HIST - 1;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL , 1, MIBTail, snmp_prfProtoFn,
	LEN_SQ_PRF + 5, LEN_SQ_PRF + 3);

    return ret;
}


oid_ParseFn *
netdbGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("netdbGetFn: called with %d %p\n", SrcLen,Src);
    if (SrcLen != LEN_SQ_PRF + 7)
	return NULL;

    return snmp_netdbFn;
}

oid_ParseFn *
netdbGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_NET, NET_NETDBTBL, 1};
    int MIBRootLen = LEN_SQ_NET + 2;
    oid MIBTail[LEN_SQ_SYS + 7] =
    {SQ_NET, NET_NETDBTBL, 1, NETDB_END - 1, 0, 0, 0, 0};
    oid_ParseFn *ret;
#if 0
    int max;
#endif
    debug(49, 5) ("netdbGetNextFn: called with %d\n", SrcLen);
    addr2oid( *gen_getMax(), &MIBTail[LEN_SQ_MESH +3] );

    print_oid(MIBTail, LEN_SQ_NET + 7);
    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, netdbGetRowFn , 4, MIBTail, snmp_netdbFn,
	LEN_SQ_NET + 7, LEN_SQ_NET + 2);
    return ret;
}

oid_ParseFn *
dnsGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("dnsGetFn: called with %d\n", SrcLen);
    if (SrcLen != LEN_SQ_NET + 5)
	return NULL;

    return snmp_dnsFn;
}

oid_ParseFn *
dnsGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    oid MIBRoot[] =
    {SQ_NET, NET_DNS, NET_DNS_IPCACHE, 1, 1};
    int MIBRootLen = LEN_SQ_NET + 3;
    oid MIBTail[LEN_SQ_NET + 5] =
    {SQ_NET, NET_DNS, NET_DNS_IPCACHE, 1, NET_IPC_END - 1, 0};
    oid_ParseFn *ret;
    int max;

    debug(49, 5) ("dnsGetNextFn: called with %d\n", SrcLen);
    print_oid(Src, SrcLen);
    if (Src[LEN_SQ_NET + 1] <= NET_DNS_IPCACHE) {
	/* number of ip cache entries */
	max = ipcache_getMax();
	if (!max)
	    return NULL;

	MIBTail[LEN_SQ_NET + 4] = max;
	debug(49, 6) ("dnsGetNextFn: Tail is:\n");
	print_oid(MIBTail, LEN_SQ_NET + 5);
	ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	    MIBRoot, MIBRootLen, NULL , 1 , MIBTail, snmp_dnsFn,
	    LEN_SQ_NET + 5, LEN_SQ_NET + 3);
	if (ret)
	    return ret;
    }
    max = fqdn_getMax();
    if (!max)
	return NULL;

    MIBRoot[LEN_SQ_NET + 1] = NET_DNS_FQDNCACHE;
    MIBTail[LEN_SQ_NET + 4] = max;
    MIBTail[LEN_SQ_NET + 3] = NET_FQDN_END - 1;
    MIBTail[LEN_SQ_NET + 1] = NET_DNS_FQDNCACHE;

    /* number of fqdn cache entries */
    MIBTail[LEN_SQ_NET + 4] = fqdn_getMax();
    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, NULL , 1, MIBTail, snmp_dnsFn,
	LEN_SQ_NET + 5, LEN_SQ_NET + 3);
    return ret;
}

oid_ParseFn *
secGetFn(oid * Src, snint SrcLen)
{
    return NULL;
}

oid_ParseFn *
secGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    return NULL;
}

oid_ParseFn *
accGetFn(oid * Src, snint SrcLen)
{
    return NULL;
}

oid_ParseFn *
accGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint *DestLen)
{
    return NULL;
}


struct in_addr *
gen_getMax()
{
        static struct in_addr maddr;
#if USE_ICMP
        safe_inet_addr("255.255.255.255", &maddr);
#else
        safe_inet_addr("0.0.0.0", &maddr);
#endif
        return &maddr;
}

int fd_getMax()
{
	fde *f;
	int cnt=0,num=0;
        while (cnt < Squid_MaxFD) {
            f = &fd_table[cnt++];
            if (!f->open)
                continue;
            if (f->type!=FD_SOCKET)
                num++;
        }
	return num;
}
