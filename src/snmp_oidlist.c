
#include "squid.h"
#include "snmp.h"
#include "asn1.h"
#include "snmp_vars.h"
#include "cache_snmp.h"
#include "snmp_oidlist.h"


/*
 * squid is under:   .1.3.6.1.3.25.17   ( length=7)
 */

oid_ParseFn *
genericGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen,
    oid * mibRoot, int mibRootLen, oid_GetRowFn * getRowFn, int mibRowLen, oid * mibTail,
    oid_ParseFn * mygetFn, int mibTailLen, int mibActionIndex)
{
    int ret;
    oid *Ptr;
    int i = 0;
    oid nullOid[] =
    {0, 0, 0, 0, 0};

    debug(49, 8) ("genericGetNextFn: Called with root=%d, tail=%d index=%d, mibRowLen=%d:\n",
	mibRootLen, mibTailLen, mibActionIndex, mibRowLen);
    snmpDebugOid(8, mibRoot, mibRootLen);

    ret = oidcmp(Src, SrcLen, mibRoot, mibRootLen);
    if ((ret < 0) || (ret == 0)) {
	/* The requested OID is before this MIB.  Return the first
	 * entry.
	 */
	*DestLen = mibTailLen;
	*Dest = (oid *) xmalloc(sizeof(oid) * (*DestLen));
	if (*Dest == NULL)
	    return (NULL);

	/* Initialize the OID to the first action */
	xmemcpy((oid *) * Dest, (oid *) mibTail, (mibTailLen * sizeof(oid)));

	/* Set this to action 1 */
	Ptr = *Dest;

	Ptr[mibActionIndex] = 1;
	if (!getRowFn)
	    Ptr[mibTailLen - 1] = 1;
	else if (!getRowFn(&Ptr[mibTailLen - mibRowLen], nullOid))
	    return NULL;

	debug(49, 6) ("genericGetNextFn:  On this mib (%d).\n", mibActionIndex);
	return (mygetFn);
    }
    ret = oidcmp(Src, SrcLen, mibTail, mibTailLen);
    if (ret > 0) {
	/* Beyond us. */
	debug(49, 8) ("genericGetNextFn:  Beyond this mib.  Returning nothing.\n");
	snmpDebugOid(8, Src, SrcLen);
	snmpDebugOid(8, mibTail, mibTailLen);
	return (NULL);
    }
    /* Ok. Let's copy the first mibTailLen parts of the OID.  That's
     * all this MIB really cares about.
     */
    *DestLen = mibTailLen;

    /* Allocate space for the new OID */
    *Dest = (oid *) xmalloc(sizeof(oid) * (*DestLen));
    if (*Dest == NULL)
	return (NULL);

    /* Initialize the OID to the first action
     *
     * Incoming OID must be at least (mibRootLen)+1 bytes.  Less would
     * have already been returned.
     */
    Ptr = *Dest;
    debug(49, 9) ("genericGetNextFn: SrcLen=%d , mibTailLen=%d\n",
	SrcLen, mibTailLen);
    if (SrcLen <= mibTailLen) {
	/* Copy everything we can, and fill in the blanks */
	debug(49, 5) ("genericGetNextFn: Adding missing information.\n");
	xmemcpy(Ptr, Src, (SrcLen * sizeof(oid)));

	if (SrcLen != mibTailLen) {
	    for (i = SrcLen - 1; i < mibTailLen; i++)
		Ptr[i] = 1;
	    if (getRowFn)
		if (!getRowFn(&Ptr[mibTailLen - mibRowLen], nullOid)) {
		    debug(49, 5) ("genericGetNextFn: End of Table.\n");
		    return NULL;
		}
	}
    } else {
	/* Src too long.  Just copy the first part. */
	xmemcpy(Ptr, Src, (mibTailLen * sizeof(oid)));
    }


    /* Look at the next item */

    if (getRowFn) {
	if (!getRowFn(&Ptr[mibTailLen - mibRowLen], &Ptr[mibTailLen - mibRowLen])) {
	    debug(49, 5) ("genericGetNextFn:end of row!\n");
	    /* no more rows, next action or finished. */
	    Ptr[mibActionIndex]++;
	    if (Ptr[mibActionIndex] > mibTail[mibActionIndex]) {
		debug(49, 5) ("genericGetNextFn:Beyond last action! (%d)\n",
		    Ptr[mibActionIndex]);
		xfree(*Dest);
		return (NULL);
	    }
	    assert(getRowFn(&Ptr[mibTailLen - mibRowLen], nullOid));
	}
    } else {

	Ptr[mibTailLen - 1]++;

	if (Ptr[mibTailLen - 1] > mibTail[mibTailLen - 1]) {
	    /* Too far! */
	    if (mibTailLen > mibRootLen + 1) {
		Ptr[mibActionIndex]++;
		Ptr[mibTailLen - 1] = 1;
		if (Ptr[mibActionIndex] > mibTail[mibActionIndex]) {
		    debug(49, 5) ("genericGetNextFn:Beyond last action! (%d)\n",
			Ptr[mibActionIndex]);
		    xfree(*Dest);
		    return (NULL);
		}
	    } else {
		debug(49, 5) ("genericGetNextFn:Beyond last entry! (%d)\n", Ptr[mibTailLen - 1]);
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
    debug(49, 5) ("basicGetFn: called for %d\n", Src[7]);
    if (((SrcLen == (LEN_SYSMIB + 1)) ||
	    ((SrcLen == (LEN_SYSMIB + 2)) && (Src[LEN_SYSMIB + 1] == 0))) &&
	(Src[LEN_SYSMIB] > 0) &&
	(Src[LEN_SYSMIB] < SYS_END))
	return (snmp_basicFn);

    return NULL;
}
oid_ParseFn *
basicGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid_ParseFn *retFn = NULL;
    oid mibRoot[] =
    {SYSMIB};
    int mibRootLen = LEN_SYSMIB;
    oid mibTail[LEN_SYSMIB + 1] =
    {SYSMIB, SYSMIB_END - 1};

    retFn = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_basicFn,
	LEN_SYSMIB + 1, LEN_SYSMIB);

    return retFn;
}


oid_ParseFn *
sysGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("sysGetFn: here! with Src[8]=%d\n", Src[8]);
    if ((SrcLen == LEN_SQ_SYS + 4 && Src[LEN_SQ_SYS] == SYSFDTBL) ||
	(SrcLen == LEN_SQ_SYS + 8 && Src[LEN_SQ_SYS] == SYSCONNTBL))
	return snmp_sysFn;
    if (SrcLen != LEN_SQ_SYS + 1)
	return NULL;
    if (Src[LEN_SQ_SYS] > 0 && Src[LEN_SQ_SYS] < 3)
	return snmp_sysFn;

    return NULL;
}

oid_ParseFn *
sysGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_SYS};
    int mibRootLen = LEN_SQ_SYS;
    oid mibTail[LEN_SQ_SYS + 1] =
    {SQ_SYS, 2};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_sysFn,
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
sysConnGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_SYS, SYSCONNTBL};
    int mibRootLen = LEN_SQ_SYS + 1;
    oid mibTail[LEN_SQ_SYS + 8] =
    {SQ_SYS, SYSCONNTBL, 1, SYS_CONN_END - 1, 0, 0, 0, 0, 0};
    oid_ParseFn *ret;

    addr2oid(*gen_getMax(), &mibTail[LEN_SQ_MESH + 3]);
    mibTail[LEN_SQ_SYS + 7] = 0;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, sysConnGetRowFn, 5, mibTail, snmp_sysFn,
	LEN_SQ_SYS + 8, LEN_SQ_SYS + 2);
    return ret;
}

oid_ParseFn *
sysFdGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_SYS, SYSFDTBL};
    int mibRootLen = LEN_SQ_SYS + 1;
    oid mibTail[LEN_SQ_SYS + 4] =
    {SQ_SYS, SYSFDTBL, 1, SYS_FD_END - 1, 0};
    oid_ParseFn *ret;

    mibTail[LEN_SQ_SYS + 3] = fd_getMax();

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_sysFn,
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
confGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_CONF};
    int mibRootLen = LEN_SQ_CONF;
    oid mibTail[LEN_SQ_CONF + 1] =
    {SQ_CONF, CONF_LOG_FAC};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_confFn,
	LEN_SQ_CONF + 1, LEN_SQ_CONF);
    return ret;
}

oid_ParseFn *
confStGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_CONF, CONF_STORAGE};
    int mibRootLen = LEN_SQ_CONF + 1;
    oid mibTail[LEN_SQ_CONF + 2] =
    {SQ_CONF, CONF_STORAGE, CONF_ST_END - 1};
    oid_ParseFn *ret;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_confFn,
	LEN_SQ_CONF + 2, LEN_SQ_CONF + 1);
    return ret;
}

int
sysConnGetRowFn(oid * New, oid * Oid)
{
    int cnt = 0, act = 0;
    int port = 0;
    static char buf[16];
    static fde *f = NULL;
    static fde *ff = NULL;

    if (!Oid[0] && !Oid[1] && !Oid[2] && !Oid[3])
	act = 1;
    else {
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", Oid[0], Oid[1], Oid[2], Oid[3]);
	port = Oid[4];
	debug(49, 9) ("sysConnGetRowFn: input [%s]:%d\n", buf, port);
    }
    while (cnt < Squid_MaxFD) {
	f = &fd_table[cnt++];
	if (!f->open)
	    continue;
	if (f->type == FD_SOCKET && f->remote_port != 0) {
	    debug(49, 9) ("sysConnGetRowFn: now [%s]:%d\n", f->ipaddr, f->remote_port);
	    if (ff)
		debug(49, 9) ("sysConnGetRowFn: prev [%s]:%d\n", ff->ipaddr, ff->remote_port);
	    if (act || (ff && !strcmp(ff->ipaddr, buf) && (port == ff->remote_port)))
		break;
	    ff = f;
	}
    }
    if (!f || f->type != FD_SOCKET || !f->ipaddr) {
	debug(49, 9) ("sysConnGetRowFn: returning 0\n", buf);
	return 0;
    }
    debug(49, 9) ("sysConnGetRowFn: returning [%s]:%d\n", f->ipaddr, f->remote_port);
    sscanf(f->ipaddr, "%d.%d.%d.%d", &New[0], &New[1], &New[2], &New[3]);
    New[4] = f->remote_port;
    return 1;
}

int
meshPtblGetRowFn(oid * New, oid * Oid)
{
    peer *p;
    struct in_addr *maddr;
    if (!Oid[0] && !Oid[1] && !Oid[2] && !Oid[3])
	p = Config.peers;
    else {
	maddr = oid2addr(Oid);
	for (p = Config.peers; p != NULL; p = p->next) {
	    if (p->in_addr.sin_addr.s_addr ==
		maddr->s_addr)
		break;
	}
	if (!p || !p->next)
	    return 0;
	p = p->next;
    }
    addr2oid(p->in_addr.sin_addr, New);
    return 1;
}

oid_ParseFn *
meshPtblGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_MESH, MESH_PTBL};
    int mibRootLen = LEN_SQ_MESH + 1;
    oid mibTail[LEN_SQ_MESH + 7] =
    {SQ_MESH, MESH_PTBL, 1, MESH_PTBL_END - 1, 0, 0, 0, 0};
    int numPeers = 0;
    snint max_addr = 0;
    oid_ParseFn *ret;
    /* XXX should be smarter than that */
    peer *pp = NULL;
    peer *p = Config.peers;
    debug(49, 6) ("meshPtblGetNextFn: called\n");
    while (p) {
	numPeers++;
	if (p->in_addr.sin_addr.s_addr > max_addr) {
	    max_addr = p->in_addr.sin_addr.s_addr;
	    pp = p;
	}
	p = p->next;
    }
    if (pp != NULL) {
	addr2oid(pp->in_addr.sin_addr, &mibTail[LEN_SQ_MESH + 3]);

	ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	    mibRoot, mibRootLen, meshPtblGetRowFn, 4, mibTail, snmp_meshPtblFn,
	    LEN_SQ_MESH + 7, LEN_SQ_MESH + 2);
    } else {
	ret = NULL;
    }
    return ret;
}

oid_ParseFn *
meshCtblGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_MESH, MESH_CTBL};
    int mibRootLen = LEN_SQ_MESH + 1;
    oid mibTail[LEN_SQ_MESH + 7] =
    {SQ_MESH, MESH_CTBL, 1, MESH_CTBL_END - 1, 0, 0, 0, 0};
    oid_ParseFn *ret;

    debug(49, 6) ("meshCtblGetNextFn: called\n");
    addr2oid(*gen_getMax(), &mibTail[LEN_SQ_MESH + 3]);

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, meshCtblGetRowFn, 4, mibTail, snmp_meshCtblFn,
	LEN_SQ_MESH + 7, LEN_SQ_MESH + 2);
    return ret;
}

oid_ParseFn *
prfSysGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("prfSysGetFn: called.\n");

    if (SrcLen != LEN_SQ_PRF + 2 || Src[LEN_SQ_PRF + 1] >= PERF_SYS_END)
	return NULL;
    return snmp_prfSysFn;
}

oid_ParseFn *
prfSysGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_PRF, PERF_SYS};
    int mibRootLen = LEN_SQ_PRF + 1;
    oid mibTail[LEN_SQ_PRF + 2] =
    {SQ_PRF, PERF_SYS, PERF_SYS_END - 1};

    debug(49, 5) ("prfSysGetNextFn: called.\n");

    return genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_prfSysFn,
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
prfProtoGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, 1, 0, 0};
    int mibRootLen = LEN_SQ_PRF + 2;
    oid mibTail[] =
    {SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_END - 1, 0, 0, 0};
    oid_ParseFn *ret;

    if (Src[LEN_SQ_PRF + 1] <= PERF_PROTOSTAT_AGGR) {
	ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	    mibRoot, mibRootLen, NULL, 1, mibTail, snmp_prfProtoFn,
	    LEN_SQ_PRF + 3, LEN_SQ_PRF + 2);
	if (ret)
	    return ret;
    }
    mibRoot[LEN_SQ_PRF + 1] = PERF_PROTOSTAT_MEDIAN;
    mibRoot[LEN_SQ_PRF + 2] = 1;
    mibRoot[LEN_SQ_PRF + 3] = 1;
    mibRootLen += 1;
    mibTail[LEN_SQ_PRF + 1] = PERF_PROTOSTAT_MEDIAN;
    mibTail[LEN_SQ_PRF + 2] = 1;
    mibTail[LEN_SQ_PRF + 3] = PERF_MEDIAN_END - 1;
    mibTail[LEN_SQ_PRF + 4] = N_COUNT_HIST - 1;

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_prfProtoFn,
	LEN_SQ_PRF + 5, LEN_SQ_PRF + 3);

    return ret;
}


oid_ParseFn *
netdbGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("netdbGetFn: called with %d %p\n", SrcLen, Src);
    if (SrcLen != LEN_SQ_PRF + 7)
	return NULL;

    return snmp_netdbFn;
}

oid_ParseFn *
netdbGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_NET, NET_NETDBTBL, 1};
    int mibRootLen = LEN_SQ_NET + 2;
    oid mibTail[LEN_SQ_SYS + 7] =
    {SQ_NET, NET_NETDBTBL, 1, NETDB_END - 1, 0, 0, 0, 0};
    oid_ParseFn *ret;

    debug(49, 6) ("netdbGetNextFn: called\n", SrcLen);
    addr2oid(*gen_getMax(), &mibTail[LEN_SQ_MESH + 3]);

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, netdbGetRowFn, 4, mibTail, snmp_netdbFn,
	LEN_SQ_NET + 7, LEN_SQ_NET + 2);
    return ret;
}

oid_ParseFn *
dnsGetFn(oid * Src, snint SrcLen)
{
    debug(49, 6) ("dnsGetFn: called\n");
    if (SrcLen != LEN_SQ_NET + 5)
	return NULL;

    return snmp_dnsFn;
}

oid_ParseFn *
dnsGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_NET, NET_DNS, NET_DNS_IPCACHE, 1, 1};
    int mibRootLen = LEN_SQ_NET + 3;
    oid mibTail[LEN_SQ_NET + 5] =
    {SQ_NET, NET_DNS, NET_DNS_IPCACHE, 1, NET_IPC_END - 1, 0};
    oid_ParseFn *ret;
    int max;

    debug(49, 6) ("dnsGetNextFn: called\n");
    if (Src[LEN_SQ_NET + 1] <= NET_DNS_IPCACHE) {
	/* number of ip cache entries */
	max = ipcache_getMax();
	if (!max)
	    return NULL;

	mibTail[LEN_SQ_NET + 4] = max;
	ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	    mibRoot, mibRootLen, NULL, 1, mibTail, snmp_dnsFn,
	    LEN_SQ_NET + 5, LEN_SQ_NET + 3);
	if (ret)
	    return ret;
    }
    max = fqdn_getMax();
    if (!max)
	return NULL;

    mibRoot[LEN_SQ_NET + 1] = NET_DNS_FQDNCACHE;
    mibTail[LEN_SQ_NET + 4] = max;
    mibTail[LEN_SQ_NET + 3] = NET_FQDN_END - 1;
    mibTail[LEN_SQ_NET + 1] = NET_DNS_FQDNCACHE;

    /* number of fqdn cache entries */
    mibTail[LEN_SQ_NET + 4] = fqdn_getMax();
    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_dnsFn,
	LEN_SQ_NET + 5, LEN_SQ_NET + 3);
    return ret;
}
