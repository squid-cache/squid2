

/*
 * snmp_auth.c -
 *   Authentication for SNMP (RFC 1067).  This implements a null
 * authentication layer.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
#include <stdio.h>

#ifdef KINETICS
#include "gw.h"
#include "fp4/cmdmacro.h"
#endif

#ifdef linux
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#endif


#if (defined(unix) && !defined(KINETICS))
#include <sys/types.h>
#include <netinet/in.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"

u_char *
snmp_auth_parse(data, length, sid, slen, version)
     u_char *data;
     int *length;
     u_char *sid;
     int *slen;
     long *version;
{
    u_char type;

    data = asn_parse_header(data, length, &type);
    if (data == NULL) {
	ERROR("bad header");
	return NULL;
    }
    if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
	ERROR("wrong auth header type");
	return NULL;
    }
    data = asn_parse_int(data, length, &type, version, sizeof(*version));
    if (data == NULL) {
	ERROR("bad parse of version");
	return NULL;
    }
    data = asn_parse_string(data, length, &type, sid, slen);
    if (data == NULL) {
	ERROR("bad parse of community");
	return NULL;
    }
    if (*version == SNMP_VERSION_1)
	sid[*slen] = '\0';
    return (u_char *) data;
}

u_char *
snmp_auth_build(data, length, session, is_agent, messagelen)
     u_char *data;
     int *length;
     struct snmp_session *session;
     int is_agent;
     int messagelen;
{
    u_char *params;
    int plen;

    if (session->version == SNMP_VERSION_2) {
	u_char buff[138];	/* max len of param string */
	u_char *pp = buff;
	u_long tmp;

	*pp++ = SNMP_USEC_MODEL;	/* usec model */

	*pp++ = session->qoS;

	memcpy(pp, session->agentID, 12);
	pp += 12;

	if (is_agent || session->qoS & USEC_QOS_AUTH) {
	    tmp = session->agentBoots;
	    *pp++ = (tmp >> 24) & 0xff;
	    *pp++ = (tmp >> 16) & 0xff;
	    *pp++ = (tmp >> 8) & 0xff;
	    *pp++ = tmp & 0xff;
	} else {
	    memset(pp, 0, 4);
	    pp += 4;
	}

	if (is_agent || session->qoS & USEC_QOS_AUTH) {
	    tmp = session->agentClock + time(NULL);
	    *pp++ = (tmp >> 24) & 0xff;
	    *pp++ = (tmp >> 16) & 0xff;
	    *pp++ = (tmp >> 8) & 0xff;
	    *pp++ = tmp & 0xff;
	} else {
	    memset(pp, 0, 4);
	    pp += 4;
	}

	tmp = session->MMS;
	*pp++ = (tmp >> 8) & 0xff;
	*pp++ = tmp & 0xff;

	*pp++ = session->userLen;
	memcpy(pp, session->userName, session->userLen);
	pp += session->userLen;

	if (session->qoS & USEC_QOS_AUTH) {
	    *pp++ = 16;
	    memcpy(pp, session->authKey, 16);
	    pp += 16;
	} else {
	    *pp++ = 0;
	}

	memcpy(pp, session->contextSelector, session->contextLen);
	pp += session->contextLen;

	params = buff;
	plen = pp - buff;
    } else {
	params = session->community;
	plen = session->community_len;
    }

    data = asn_build_sequence(data, length, (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
	messagelen + plen + 5);
    if (data == NULL) {
	ERROR("buildheader");
	return NULL;
    }
    data = asn_build_int(data, length,
	(u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	(long *) &session->version, sizeof(session->version));
    if (data == NULL) {
	ERROR("buildint");
	return NULL;
    }
    data = asn_build_string(data, length,
	(u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR), params, plen);
    if (data == NULL) {
	ERROR("buildstring");
	return NULL;
    }
    return (u_char *) data;
}
