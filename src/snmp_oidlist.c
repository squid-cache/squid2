#include "squid.h"
#include "snmp.h"
#include "asn1.h"
#include "snmp_vars.h"
#include "snmp_oidlist.h"
#include "cache_snmp.h"

/*
 * squid is under:   .1.3.6.1.3.25.17   ( length=7)
 */
#ifndef MIN
#define MIN(a,b) (a<b?a:b)
#endif

/**********************************************************************/

/* First, we have a huge array of MIBs this agent knows about */

/* group handler definition */

oid_ParseFn *basicGetFn(oid *, long);
oid_ParseFn *basicGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *sysGetFn(oid *, long);
oid_ParseFn *sysGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *sysFdGetFn(oid *, long);
oid_ParseFn *sysFdGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *confGetFn(oid *, long);
oid_ParseFn *confGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *confPtblGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *confStGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *confTioGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *prfSysGetFn(oid *, long);
oid_ParseFn *prfSysGetFn(oid *, long);
oid_ParseFn *prfSysGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *prfPeerGetFn(oid *, long);
oid_ParseFn *prfPeerGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *prfProtoGetFn(oid *, long);
oid_ParseFn *prfProtoGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *netdbGetFn(oid *, long);
oid_ParseFn *netdbGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *dnsGetFn(oid *, long);
oid_ParseFn *dnsGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *secGetFn(oid *, long);
oid_ParseFn *secGetNextFn(oid *, long, oid **, long *);
oid_ParseFn *accGetFn(oid *, long);
oid_ParseFn *accGetNextFn(oid *, long, oid **, long *);

oid_ParseFn *genericGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen,
    oid * MIBRoot, int MIBRootLen, int LEN_MIB, oid * MIBTail,
    oid_ParseFn * mygetFn, int MIBTailLen, int MIB_ACTION_INDEX);

struct MIBListEntry MIBList[] =
{
    {
	{SYSMIB}, LEN_SYSMIB, basicGetFn, basicGetNextFn},
    {
	{SQ_SYS}, LEN_SQ_SYS, sysGetFn, sysGetNextFn},
    {
	{SQ_SYS, 3}, LEN_SQ_SYS + 1, sysFdGetFn, sysFdGetNextFn},
    {
	{SQ_CONF}, LEN_SQ_CONF, confGetFn, confGetNextFn},
    {
	{SQ_CONF, 6}, LEN_SQ_CONF + 1, confGetFn, confPtblGetNextFn},
    {
	{SQ_CONF, 7}, LEN_SQ_CONF + 1, confGetFn, confStGetNextFn},
    {
	{SQ_CONF, 8}, LEN_SQ_CONF + 1, confGetFn, confTioGetNextFn},
    {
	{SQ_PRF, 1}, LEN_SQ_PRF + 1, prfSysGetFn, prfSysGetNextFn},
    {
	{SQ_PRF, 2}, LEN_SQ_PRF + 1, prfProtoGetFn, prfProtoGetNextFn},
    {
	{SQ_PRF, 3}, LEN_SQ_PRF + 1, prfPeerGetFn, prfPeerGetNextFn},
    {
	{SQ_NET, 1}, LEN_SQ_NET + 1, netdbGetFn, netdbGetNextFn},
    {
	{SQ_NET, 2}, LEN_SQ_NET + 1, dnsGetFn, dnsGetNextFn},
    {
	{SQ_SEC}, LEN_SQ_SEC, secGetFn, secGetNextFn},
    {
	{SQ_ACC}, LEN_SQ_ACC, accGetFn, accGetNextFn},
    {
	{0}, 0, NULL, NULL}
};

extern int fqdn_getMax(), ipcache_getMax();
extern int netdb_getMax();

/**********************************************************************
 * General OID Functions
 **********************************************************************/
void 
print_oid(oid * Name, long Len)
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
oidcmp(oid * A, long ALen, oid * B, long BLen)
{
    oid *aptr = A;
    oid *bptr = B;
    long m = MIN(ALen, BLen);

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
oidncmp(oid * A, long ALen, oid * B, long BLen, long CompLen)
{
    oid *aptr = A;
    oid *bptr = B;
    long m = MIN(MIN(ALen, BLen), CompLen);
    long count = 0;

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
oiddup(oid * A, long ALen)
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
oidlist_Find(oid * Src, long SrcLen)
{
    struct MIBListEntry *Ptr;
    int ret;

    debug(49, 5) ("SNMP OIDFIND:  Called.\n ");
    print_oid(Src, SrcLen);

    for (Ptr = MIBList; Ptr->GetFn; Ptr++) {
	debug(49, 5) ("Hmmm.. we have %d and %d\n", Ptr->NameLen, SrcLen);
	print_oid(Ptr->Name, Ptr->NameLen);

	ret = oidncmp(Src, SrcLen, Ptr->Name, Ptr->NameLen, Ptr->NameLen);

	if (!ret) {

	    /* Cool.  We found the mib it's in.  Let it find the function.
	     */
	    debug(49, 5) ("SNMP OIDFIND:  found, returning GetFn Ptr! \n");

	    return ((*Ptr->GetFn) (Src, SrcLen));
	}
	if (ret < 0) {
	    debug(49, 5) ("SNMP OIDFIND:  We just passed it, so it doesn't exist.\n ");
	    /* We just passed it, so it doesn't exist. */
	    return (NULL);
	}
    }

    debug(49, 5) ("SNMP OIDFIND:  We get here if the request was past the end.  It doesn't exist.\n");
    /* We get here if the request was past the end.  It doesn't exist. */
    return (NULL);
}
/* Find the next item.  For SNMP_PDU_GETNEXT requests. 
 *
 * Returns a pointer to the parser function, and copies the oid to dest.
 * 
 */
oid_ParseFn *
oidlist_Next(oid * Src, long SrcLen, oid ** DestP, long *DestLenP)
{
    struct MIBListEntry *Ptr;
    int ret;
    oid_ParseFn *Fn = NULL;

    debug(49, 6) ("oidlist_Next: Looking for next of:\n");
    print_oid(Src, SrcLen);

    for (Ptr = MIBList; Ptr->GetNextFn; Ptr++) {

	/* Only look at as much as we have stored */
	ret = oidncmp(Src, SrcLen, Ptr->Name, Ptr->NameLen, Ptr->NameLen);
	debug(49, 6) ("oidlist_Next: Now with ret=%d at: (Src,Ptr)\n ", ret);
	print_oid(Src, SrcLen);
	print_oid(Ptr->Name, Ptr->NameLen);

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
		    debug(49, 6) ("oidlist_Next: Not in the same mib.  Looking at the next.\n");
		    Ptr++;
		    continue;
		}
		debug(49, 6) ("oidlist_Next: Found %x\n", Fn);
		debug(49, 6) ("oidlist_Next: Next OID is:\n ");
		print_oid(*DestP, *DestLenP);
		return Fn;
	    }
	    /* Return what we found.  NULL if it wasn't in the MIB, and there
	     * were no more MIBs. 
	     */
	    debug(49, 6) ("oidlist_Next: No next mib.\n");
	    return NULL;
	}
	if (ret < 0) {
	    /* We just passed the mib it would be in.  Return 
	     * the next in this MIB.
	     */
	    debug(49, 6) ("oidlist_Next: Passed mib.  Checking this one.\n");
	    return ((*Ptr->GetNextFn) (Src, SrcLen, DestP, DestLenP));
	}
	debug(49, 6) ("oidlist_Next: Checking next MIB entry.\n");
    }

    /* We get here if the request was past the end.  It doesn't exist. */
    debug(49, 7) ("oidlist_Next: Found nothing.\n");
    return (NULL);
}



/* SQUID MIB implementation */

oid_ParseFn *
genericGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen,
    oid * MIBRoot, int MIBRootLen, int LEN_MIB, oid * MIBTail,
    oid_ParseFn * mygetFn, int MIBTailLen, int MIB_ACTION_INDEX)
{
    int ret;
    oid *Ptr;
    int i = 0;

    debug(49, 5) ("genericGetNextFn: Called with root=%d, tail=%d index=%d:\n",
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
	Ptr[MIBTailLen - 1] = 1;

	debug(49, 5) ("genericGetNextFn:  On this mib (%d).\n", MIB_ACTION_INDEX);
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
    if (SrcLen <= MIBTailLen) {
	/* Copy everything we can, and fill in the blanks */
	debug(49, 5) ("genericGetNextFn: nulling.\n");
	xmemcpy(Ptr, Src, (SrcLen * sizeof(oid)));

	if (SrcLen != MIBTailLen)
	    for (i = SrcLen - 1; i < MIBTailLen; i++)
		Ptr[i] = 1;
#if 0
	Ptr[MIB_ACTION_INDEX] = 1;	/* Prime this */
#endif
    } else {
	debug(49, 5) ("genericGetNextFn: src too long.\n");
	/* Src too long.  Just copy the first part. */
	xmemcpy(Ptr, Src, (MIBTailLen * sizeof(oid)));
    }

    debug(49, 5) ("genericGetNextFn:  (Probably) in this MIB.  Creating dest.\n");

    /* Look at the next item */
    Ptr[MIBTailLen - 1]++;

    if (Ptr[MIBTailLen - 1] > MIBTail[MIBTailLen - 1]) {
	/* Too far! */
	if (MIBTailLen > MIBRootLen + 1) {
	    Ptr[MIB_ACTION_INDEX]++;
	    Ptr[MIBTailLen - 1] = 1;
	    if (Ptr[MIB_ACTION_INDEX] > MIBTail[MIB_ACTION_INDEX]) {
		debug(49, 5) ("genericGetNextFn:Beyond last action! (%d)\n", Ptr[MIB_ACTION_INDEX]);
#if 0
		xfree(*Dest);
#endif
		return (NULL);
	    }
	} else {
	    debug(49, 5) ("genericGetNextFn:Beyond last entry! (%d)\n", Ptr[MIBTailLen - 1]);
	    xfree(*Dest);
	    return (NULL);
	}
    }
    return (mygetFn);
}

oid_ParseFn *
basicGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("basicGetFn: here! with Src[7]=%d\n", Src[7]);
    if (((SrcLen == (LEN_SYSMIB + 1)) ||
	    ((SrcLen == (LEN_SYSMIB + 2)) && (Src[LEN_SYSMIB + 1] == 0))) &&
	(Src[LEN_SYSMIB] > 0) &&
	(Src[LEN_SYSMIB] <= 8))
	return (snmp_basicFn);

    return NULL;
}
oid_ParseFn *
basicGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid_ParseFn *retFn = NULL;
    oid MIBRoot[] =
    {SYSMIB};
    int MIBRootLen = LEN_SYSMIB;
    oid MIBTail[LEN_SYSMIB + 1] =
    {SYSMIB, 8};

    retFn = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SYSMIB, MIBTail, snmp_basicFn,
	LEN_SYSMIB + 1, LEN_SYSMIB);

    return retFn;
}


oid_ParseFn *
sysGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("sysGetFn: here! with Src[8]=%d\n", Src[8]);
    if (SrcLen == LEN_SQ_SYS + 4 && Src[LEN_SQ_SYS] == SYSFDTBL)
	return snmp_sysFn;
    if (SrcLen != LEN_SQ_SYS + 1)
	return NULL;
    if (Src[LEN_SQ_SYS] > 0 && Src[LEN_SQ_SYS] <= 3)
	return snmp_sysFn;

    return NULL;
}

oid_ParseFn *
sysGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_SYS};
    int MIBRootLen = LEN_SQ_SYS;
    oid MIBTail[LEN_SQ_SYS + 1] =
    {SQ_SYS, 2};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_SYS, MIBTail, snmp_sysFn,
	LEN_SQ_SYS + 1, LEN_SQ_SYS);
    return ret;
}

oid_ParseFn *
sysFdGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("sysGetFn: here! with Src[8]=%d\n", Src[8]);
    if (SrcLen == LEN_SQ_SYS + 4 && Src[LEN_SQ_SYS] == SYSFDTBL)
	return snmp_sysFn;

    return NULL;
}

oid_ParseFn *
sysFdGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_SYS, 3};
    int MIBRootLen = LEN_SQ_SYS + 1;
    oid MIBTail[LEN_SQ_SYS + 4] =
    {SQ_SYS, SYSFDTBL, 1, SYS_FD_END - 1, 0};
    oid_ParseFn *ret;

    MIBTail[LEN_SQ_SYS + 3] = Number_FD;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_SYS + 1, MIBTail, snmp_sysFn,
	LEN_SQ_SYS + 4, LEN_SQ_SYS + 2);
    return ret;
}


oid_ParseFn *
confGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("confGetFn: here! with Src[8]=%d and %d\n", Src[8], SrcLen);

    switch (Src[LEN_SQ_CONF]) {
    case CONF_PTBL:
	if (SrcLen != LEN_SQ_CONF + 4)
	    return NULL;
	return snmp_confPtblFn;
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
confGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_CONF};
    int MIBRootLen = LEN_SQ_CONF;
    oid MIBTail[LEN_SQ_CONF + 1] =
    {SQ_CONF, CONF_LOG_LVL};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_CONF, MIBTail, snmp_confFn,
	LEN_SQ_CONF + 1, LEN_SQ_CONF);
    return ret;
}

oid_ParseFn *
confStGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_CONF, CONF_STORAGE};
    int MIBRootLen = LEN_SQ_CONF + 1;
    oid MIBTail[LEN_SQ_CONF + 2] =
    {SQ_CONF, CONF_STORAGE, CONF_ST_END - 1};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_CONF + 1, MIBTail, snmp_confFn,
	LEN_SQ_CONF + 2, LEN_SQ_CONF + 1);
    return ret;
}

oid_ParseFn *
confTioGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_CONF, CONF_TIO};
    int MIBRootLen = LEN_SQ_CONF + 1;
    oid MIBTail[LEN_SQ_CONF + 2] =
    {SQ_CONF, CONF_TIO, CONF_TIO_END - 1};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_CONF + 1, MIBTail, snmp_confFn,
	LEN_SQ_CONF + 2, LEN_SQ_CONF + 1);
    return ret;
}

oid_ParseFn *
confPtblGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_CONF, CONF_PTBL};
    int MIBRootLen = LEN_SQ_SYS + 1;
    oid MIBTail[LEN_SQ_SYS + 4] =
    {SQ_CONF, CONF_PTBL, 1, CONF_PTBL_END - 1, 0};
    int numPeers = 0;
    oid_ParseFn *ret;

    /* XXX should be smarter than that */
    peer *p = Config.peers;
    while (p) {
	numPeers++;
	p = p->next;
    }

    MIBTail[LEN_SQ_SYS + 3] = numPeers;
    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_CONF + 1, MIBTail, snmp_confPtblFn,
	LEN_SQ_CONF + 4, LEN_SQ_CONF + 2);
    return ret;
}

oid_ParseFn *
prfSysGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("prfSysGetFn: called with %d, %d, %d\n", SrcLen,
	Src[LEN_SQ_PRF + 1], LEN_SQ_PRF + 1);

    if (SrcLen != LEN_SQ_PRF + 2 || Src[LEN_SQ_PRF + 1] >= PERF_SYS_END)
	return NULL;
    return snmp_prfSysFn;
}

oid_ParseFn *
prfSysGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_PRF, PERF_SYS};
    int MIBRootLen = LEN_SQ_PRF + 1;
    oid MIBTail[LEN_SQ_PRF + 2] =
    {SQ_PRF, PERF_SYS, PERF_SYS_END - 1};

    debug(49, 5) ("prfSysGetNextFn: called.\n");

    return genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_PRF + 1, MIBTail, snmp_prfSysFn,
	LEN_SQ_PRF + 2, LEN_SQ_PRF + 1);

}

oid_ParseFn *
prfProtoGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("prfProtoGetFn: called with %d\n", SrcLen);

    if (Src[LEN_SQ_PRF]== PERF_PROTOSTAT_MEDIAN && SrcLen==LEN_SQ_PRF+5)  
	return snmp_prfProtoFn;

    if (SrcLen != LEN_SQ_PRF + 3 || Src[LEN_SQ_PRF] >= PERF_PROTOSTAT_END)
	return NULL;
    return snmp_prfProtoFn;
}

oid_ParseFn *
prfProtoGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, 1, 0, 0 };
    int MIBRootLen = LEN_SQ_PRF + 2;
    oid MIBTail[] =
    {SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_END - 1, 0, 0 ,0 };
    oid_ParseFn *ret;

    if ( Src[LEN_SQ_PRF] <= PERF_PROTOSTAT_AGGR ) {
    	ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
		MIBRoot, MIBRootLen, LEN_SQ_PRF + 1, MIBTail, snmp_prfProtoFn,
			LEN_SQ_PRF + 3, LEN_SQ_PRF + 2);
    	if (ret) 
	   return ret;
    }

    MIBRoot[LEN_SQ_PRF+1 ] = PERF_PROTOSTAT_MEDIAN;
    MIBRoot[LEN_SQ_PRF+2 ] = 1;
    MIBRoot[LEN_SQ_PRF+3 ] = 1;
    MIBRootLen+=1;
    MIBTail[LEN_SQ_PRF+1  ] = PERF_PROTOSTAT_MEDIAN;
    MIBTail[LEN_SQ_PRF+2  ] = 1;
    MIBTail[LEN_SQ_PRF+3  ] = PERF_MEDIAN_END-1;
    MIBTail[LEN_SQ_PRF+4  ] = N_COUNT_HIST-1;

    debug(49,5)("prfProtoGetNextFn: checking for medians. :\n");
    print_oid(MIBRoot, MIBRootLen);
    print_oid(MIBTail, LEN_SQ_PRF+5);

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
                MIBRoot, MIBRootLen, LEN_SQ_PRF + 1, MIBTail, snmp_prfProtoFn,
                        LEN_SQ_PRF + 5, LEN_SQ_PRF + 3);

    return ret;
}

oid_ParseFn *
prfPeerGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("prfPeerGetFn: called with %d\n", SrcLen);

    if (SrcLen != LEN_SQ_PRF + 4)
	return NULL;

    return snmp_prfPeerFn;
}

oid_ParseFn *
prfPeerGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_PRF, PERF_PEER, 1, 1};
    int MIBRootLen = LEN_SQ_PRF + 3;
    oid MIBTail[LEN_SQ_PRF + 5] =
    {SQ_PRF, PERF_PEER, 1, 1, PERF_PEERSTAT_END - 1, 0};
    int numPeers = 0;
    oid_ParseFn *ret;
    peer *p;

    debug(49, 5) ("prfPeerGetNextFn: called with %d\n", SrcLen);
    /* XXX should be smarter than that */

    p = Config.peers;
    while (p) {
	numPeers++;
	p = p->next;
    }

    MIBTail[LEN_SQ_PRF + 4] = numPeers;
    print_oid(MIBTail, LEN_SQ_PRF + 5);
    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_PRF + 1, MIBTail, snmp_prfPeerFn,
	LEN_SQ_PRF + 5, LEN_SQ_PRF + 3);
    return ret;
}

oid_ParseFn *
netdbGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("netdbGetFn: called with %d\n", SrcLen);
    if (SrcLen != LEN_SQ_PRF + 4)
	return NULL;

    return snmp_netdbFn;
}

oid_ParseFn *
netdbGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    oid MIBRoot[] =
    {SQ_NET, NET_NETDBTBL, 1};
    int MIBRootLen = LEN_SQ_NET + 2;
    oid MIBTail[LEN_SQ_SYS + 4] =
    {SQ_NET, NET_NETDBTBL, 1, NETDB_END - 1, 0};
    oid_ParseFn *ret;
    int max;
    debug(49, 5) ("netdbGetNextFn: called with %d\n", SrcLen);
    max = netdb_getMax();
    if (!max)
	return NULL;
    MIBTail[LEN_SQ_NET + 3] = max;
    print_oid(MIBTail, LEN_SQ_NET + 4);
    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	MIBRoot, MIBRootLen, LEN_SQ_PRF + 1, MIBTail, snmp_netdbFn,
	LEN_SQ_NET + 4, LEN_SQ_NET + 2);
    return ret;
}

oid_ParseFn *
dnsGetFn(oid * Src, long SrcLen)
{
    debug(49, 5) ("dnsGetFn: called with %d\n", SrcLen);
    if (SrcLen != LEN_SQ_NET + 5)
	return NULL;

    return snmp_dnsFn;
}

oid_ParseFn *
dnsGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
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
	    MIBRoot, MIBRootLen, LEN_SQ_NET + 1, MIBTail, snmp_dnsFn,
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
	MIBRoot, MIBRootLen, LEN_SQ_NET + 1, MIBTail, snmp_dnsFn,
	LEN_SQ_NET + 5, LEN_SQ_NET + 3);
    return ret;
}

oid_ParseFn *
secGetFn(oid * Src, long SrcLen)
{
    return NULL;
}

oid_ParseFn *
secGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    return NULL;
}

oid_ParseFn *
accGetFn(oid * Src, long SrcLen)
{
    return NULL;
}

oid_ParseFn *
accGetNextFn(oid * Src, long SrcLen, oid ** Dest, long *DestLen)
{
    return NULL;
}
