

/*
 * $Id$
 *
 * DEBUG: section 49    SNMP
 * AUTHOR: Kostas Anagnostakis
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

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
    oid * mibRoot, int mibRootLen, oid_GetRowFn * getRowFn, int mibRowLen,
    oid * mibTail, oid_ParseFn * mygetFn, int mibTailLen, int mibActionIndex)
{
    int ret, i = 0;
    oid *Ptr;
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

/*
 * 
 * The get and get next functions for the SQUID System Group 
 * 
 * squid.1
 * 
 */
oid_ParseFn *
sysGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("sysGetFn: here! with Src[8]=%d\n", Src[8]);
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
    {SQ_SYS, 3};
    oid_ParseFn *ret;

    debug(49, 5) ("sysGetNextFn: Called\n");

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_sysFn,
	LEN_SQ_SYS + 1, LEN_SQ_SYS);
    return ret;
}

/*
 * 
 * The get and get next functions for the SQUID Config Group
 * 
 * squid.2
 * 
 */

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

/*
 * 
 * The get and get next functions for the SQUID Performance Group
 * 
 * squid.3
 * 
 */

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

    debug(49, 7) ("prfProtoGetNextFn: Called with %d %d %d %d: \n", Src[LEN_SQ_PRF + 1], PERF_PROTOSTAT_AGGR, SrcLen, LEN_SQ_PRF);
    snmpDebugOid(7, Src, SrcLen);

    if ((Src[LEN_SQ_PRF + 1] <= PERF_PROTOSTAT_AGGR) || (Src[LEN_SQ_PRF] == 1) || ((SrcLen == 9) && (Src[LEN_SQ_PRF] == 2))) {
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

/*
 * 
 * The get and get next functions for the SQUID Network Group 
 * 
 * squid.4
 * 
 */

oid_ParseFn *
netIpGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("netIpGetFn: here! with Src[8]=%d\n", Src[8]);
    if (SrcLen != LEN_SQ_NET + 2)
	return NULL;
    if (Src[LEN_SQ_NET] == 1)
	return snmp_netIpFn;

    return NULL;
}

oid_ParseFn *
netFqdnGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("netFqdnGetFn: here! with Src[8]=%d\n", Src[8]);
    if (SrcLen != LEN_SQ_NET + 2)
	return NULL;
    if (Src[LEN_SQ_NET] == 2)
	return snmp_netFqdnFn;

    return NULL;
}

oid_ParseFn *
netDnsGetFn(oid * Src, snint SrcLen)
{
    debug(49, 5) ("netDnsGetFn: here! with Src[8]=%d\n", Src[8]);
    if (SrcLen != LEN_SQ_NET + 2)
	return NULL;
    if (Src[LEN_SQ_NET] == 3)
	return snmp_netDnsFn;

    return NULL;
}

oid_ParseFn *
netIpGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_NET, 1};
    int mibRootLen = LEN_SQ_NET + 1;
    oid mibTail[LEN_SQ_NET + 2] =
    {SQ_NET, 1, 9};
    oid_ParseFn *ret;

    debug(49, 5) ("netIpGetNextFn: Called\n");

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_netIpFn,
	LEN_SQ_NET + 2, LEN_SQ_NET + 1);
    return ret;
}

oid_ParseFn *
netFqdnGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_NET, 2};
    int mibRootLen = LEN_SQ_NET + 1;
    oid mibTail[LEN_SQ_NET + 2] =
    {SQ_NET, 2, 8};
    oid_ParseFn *ret;

    debug(49, 5) ("netFqdnGetNextFn: Called\n");

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_netFqdnFn,
	LEN_SQ_NET + 2, LEN_SQ_NET + 1);
    return ret;
}

oid_ParseFn *
netDnsGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen)
{
    oid mibRoot[] =
    {SQ_NET, 3};
    int mibRootLen = LEN_SQ_NET + 1;
    oid mibTail[LEN_SQ_NET + 2] =
    {SQ_NET, 3, 3};
    oid_ParseFn *ret;

    debug(49, 5) ("netDnsGetNextFn: Called\n");

    ret = genericGetNextFn(Src, SrcLen, Dest, DestLen,
	mibRoot, mibRootLen, NULL, 1, mibTail, snmp_netDnsFn,
	LEN_SQ_NET + 2, LEN_SQ_NET + 1);
    return ret;
}

/*
 * 
 * The get and get next functions for the SQUID Mesh Group 
 * 
 * squid.5
 * 
 */

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
