
#include "config.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "md5.h"
#include "util.h"

u_long snmpStats[SNMP_LAST_STAT + 1] =
{0};

void
hex_dump(hdr, msg, len)
     char *hdr;
     short len;
     unsigned char *msg;
{
    int i = 0;
    unsigned char ch;
    unsigned char hex[50];
    unsigned char asc[17];

    while (len--) {
	if (i == 16) {
	    asc[i] = 0;
	    fprintf(stderr, "%s%08lx %s %s\n",
		hdr, (long) msg - i, hex, asc);
	    i = 0;
	}
	ch = *msg++;
	if (isprint(ch))
	    asc[i] = ch;
	else
	    asc[i] = '.';
	sprintf(&hex[i * 3], "%02X ", ch);
	i++;
    }
    if (i) {
	asc[i] = 0;
	fprintf(stderr, "%s%08x %-48s %s\n", hdr,
	    (ssize_t) msg - i, hex, asc);
    }
}

void
v2md5auth_password_to_key(password, passwordlen, agentID, key)
     u_char *password;		/* IN */
     u_int passwordlen;		/* IN */
     u_char *agentID;		/* IN - pointer to 12 octet long agentID */
     u_char *key;		/* OUT - caller supplies pointer to 16
				 * octet buffer */
{
    MD5_CTX MD;
    u_char *cp, password_buf[64];
    u_long password_index = 0;
    u_long count = 0, i;

    MD5Init(&MD);		/* initialize MD5 */

    /* loop until we've done 1 Megabyte */
    while (count < 1048576) {
	cp = password_buf;
	for (i = 0; i < 64; i++) {
	    *cp++ = password[password_index++ % passwordlen];
	    /*
	     * Take the next byte of the password, wrapping to the
	     * beginning of the password as necessary.
	     */
	}

	MD5Update(&MD, password_buf, 64);

	/*
	 * 1048576 is divisible by 64, so the last MDupdate will be
	 * aligned as well.
	 */
	count += 64;
    }

    MD5Final(password_buf, &MD);
    memcpy(password_buf + 16, agentID, 12);
    memcpy(password_buf + 28, password_buf, 16);

    MD5Init(&MD);		/* initialize MD5 */
    MD5Update(&MD, password_buf, 44);
    MD5Final(key, &MD);
}

void
md5Digest(u_char *msg, int length, u_char *key, u_char *digest)
{
    MD5_CTX MD;

    MD5Init(&MD);		/* initialize MD5 */
    MD5Update(&MD, msg, length);
    MD5Update(&MD, key, 16);
    MD5Final(digest, &MD);
}

/*
 * this routine is used to parse a community string that is passed as
 * a command line option to an application (management entity) program
 */
int
parse_app_community_string(session)
     struct snmp_session *session;
{
    u_char *cp = session->community;
    u_char *start;
    int ch;
    int i;

    /* community string is a v2u community if it begins with '/' */
    if (*cp == '/') {
	cp++;

	start = cp;
	while (*cp && *cp != '/')
	    cp++;
	session->userLen = cp - start;
	strncpy(session->userName, start, cp - start);
	session->userName[cp - start] = 0;

	if (session->userLen == 0) {
	    fprintf(stderr, "userName cannot be zero length\n");
	    return -1;
	}
	session->qoS = 0;
	session->version = SNMP_VERSION_2;
	session->MMS = SNMP_MAX_LEN;

	/* look for authKey */
	if (*cp != '/')
	    return 0;
	cp++;

	start = cp;
	while (*cp && *cp != '/')
	    cp++;
	if ((cp - start > 2) && (strncmp(start, "0x", 2) == 0)) {
	    if (cp - start != 34) {
		fprintf(stderr, "auth key not 16 octets\n");
		return -1;
	    }
	    start += 2;
	    for (i = 0; i < 16; i++) {
		if (sscanf(start, "%2x", &ch) != 1) {
		    fprintf(stderr, "auth key contains non hex digits\n");
		    return -1;
		}
		start += 2;
		session->authKey[i] = ch;
	    }
	    session->qoS |= USEC_QOS_AUTH;
	} else if (cp - start > 0) {
	    v2md5auth_password_to_key(start, cp - start, session->agentID, session->authKey);
	    session->qoS |= USEC_QOS_AUTH;
	}
	/* look for privKey */
	if (*cp != '/')
	    return 0;
	cp++;

	start = cp;
	while (*cp && *cp != '/')
	    cp++;
	if ((cp - start > 2) && (strncmp(start, "0x", 2) == 0)) {
	    if (cp - start != 34) {
		fprintf(stderr, "priv key not 16 octets\n");
		return -1;
	    }
	    start += 2;
	    for (i = 0; i < 16; i++) {
		if (sscanf(start, "%2x", &ch) != 1) {
		    fprintf(stderr, "priv key contains non hex digits\n");
		    return -1;
		}
		session->privKey[i] = ch;
		start += 2;
	    }
	    session->qoS |= USEC_QOS_PRIV;
	} else if (cp - start > 0) {
	    v2md5auth_password_to_key(start, cp - start, session->privKey);
	    session->qoS |= USEC_QOS_PRIV;
	}
	/* look for contextSelector */
	if (*cp != '/')
	    return 0;
	cp++;

	start = cp;
	while (*cp && *cp != '/')
	    cp++;
	session->contextLen = cp - start;
	strncpy(session->contextSelector, start, cp - start);
    }
    return 0;
}

void
increment_stat(stat)
     int stat;
{
    snmpStats[stat]++;
}

void
create_report(session, out_data, out_length, stat, reqid)
     struct snmp_session *session;
     u_char *out_data;
     int *out_length;
     int stat;
     int reqid;
{
    struct snmp_pdu *report;
    static oid name[] =
    {1, 3, 6, 1, 6, 3, 0, 1, 1, 0, 0};
    int name_length = 11;

    switch (stat) {
    case SNMP_STAT_ENCODING_ERRORS:
	name[6] = 1;
	name[8] = 1;
	name[9] = 3;
	break;
    case USEC_STAT_UNSUPPORTED_QOS:
	name[6] = 6;
	name[8] = 2;
	name[9] = 1;
	break;
    case USEC_STAT_NOT_IN_WINDOWS:
	name[6] = 6;
	name[8] = 2;
	name[9] = 2;
	break;
    case USEC_STAT_UNKNOWN_USERNAMES:
	name[6] = 6;
	name[8] = 2;
	name[9] = 3;
	break;
    case USEC_STAT_WRONG_DIGEST_VALUES:
	name[6] = 6;
	name[8] = 2;
	name[9] = 4;
	break;
    case USEC_STAT_UNKNOWN_CONTEXT_SELECTORS:
	name[6] = 6;
	name[8] = 2;
	name[9] = 5;
	break;
    case SNMP_STAT_BAD_OPERATIONS:
	name[6] = 1;
	name[8] = 1;
	name[9] = 11;
	break;
    case SNMP_STAT_PROXY_DROPS:
	name[6] = 1;
	name[8] = 1;
	name[9] = 13;
	break;
    case SNMP_STAT_SILENT_DROPS:
	name[6] = 1;
	name[8] = 1;
	name[9] = 12;
	break;
    default:
	return;
    }

    if ((session->qoS & USEC_QOS_AUTH) && (stat == USEC_STAT_NOT_IN_WINDOWS)) {
	session->qoS = USEC_QOS_AUTH;
    } else {
	session->qoS = USEC_QOS_NOAUTH_NOPRIV;
    }

    report = snmp_pdu_create(REPORT_MSG);
    report->errstat = 0;
    report->errindex = 0;
    report->reqid = reqid;
    snmp_add_null_var(report, name, name_length);
    report->variables->type = COUNTER;
    report->variables->val.string = xcalloc(1, sizeof(u_long));
    report->variables->val_len = sizeof(u_long);
    *(u_long *) report->variables->val.string = snmpStats[stat];
    snmp_build(session, report, out_data, out_length, 1);

/** snmp_free_pdu( report ); **/
}

int
parse_parameters(pp, plen, params)
     u_char *pp;
     int plen;
     Parameters *params;
{
    /* 25 octets -- <model><qoS><agentID><agentBoots><agentTime><mms><userLen> */
    if (plen < 25)
	return USEC_STAT_BAD_PARAMETERS;

    params->securityModel = pp[0];
    if (params->securityModel != SNMP_USEC_MODEL)
	return USEC_STAT_BAD_PARAMETERS;

    params->qoS = pp[1];
    if ((params->qoS & ~(USEC_QOS_AUTH | USEC_QOS_GENREPORT)))
	return USEC_STAT_BAD_PARAMETERS;

    memcpy(params->agentID, &pp[2], sizeof(params->agentID));

    params->agentBoots = (pp[14] << 24) + (pp[15] << 16) + (pp[16] << 8) + pp[17];

    params->agentTime = (pp[18] << 24) + (pp[19] << 16) + (pp[20] << 8) + pp[21];

    params->MMS = (pp[22] << 8) + pp[23];
    if (params->MMS < 484)
	return USEC_STAT_BAD_PARAMETERS;

    params->userLen = pp[24];
    if (params->userLen == 0 || params->userLen > sizeof(params->userName))
	return USEC_STAT_BAD_PARAMETERS;

    plen = plen - 25 - params->userLen;
    pp += 25;
    if (plen < 1)
	return USEC_STAT_BAD_PARAMETERS;

    memcpy(params->userName, pp, params->userLen);
    pp += params->userLen;

    params->authLen = *pp++;
    plen--;
    if (params->qoS & USEC_QOS_AUTH) {
	if (plen < 16 || params->authLen != 16)
	    return USEC_STAT_BAD_PARAMETERS;
	memcpy(params->authDigest, pp, 16);
	params->authDigestPtr = pp;
	pp += 16;
	plen -= 16;
    } else if (params->authLen != 0) {
	return USEC_STAT_BAD_PARAMETERS;
    }
    params->contextLen = plen;
    if (params->contextLen > sizeof(params->contextSelector))
	return USEC_STAT_BAD_PARAMETERS;
    memcpy(params->contextSelector, pp, params->contextLen);

    return 0;
}

int
check_received_pkt(pkt, pktlen, comm, commlen, session, pdu)
     u_char *pkt;
     int pktlen;
     u_char *comm;
     int commlen;
     struct snmp_session *session;
     struct snmp_pdu *pdu;
{
    Parameters *params;

    increment_stat(SNMP_STAT_PACKETS);

    params = &pdu->params;
    if (parse_parameters(comm, commlen, params) != 0)
	return USEC_STAT_BAD_PARAMETERS;

    if (memcmp(session->agentID, params->agentID, sizeof(session->agentID)) != 0)
	return USEC_STAT_UNKNOWN_CONTEXT_SELECTORS;

    if (session->contextLen != params->contextLen ||
	memcmp(session->contextSelector, params->contextSelector,
	    session->contextLen) != 0)
	return USEC_STAT_UNKNOWN_CONTEXT_SELECTORS;

    if (session->userLen != params->userLen
	|| memcmp(session->userName, params->userName, session->userLen) != 0)
	return USEC_STAT_UNKNOWN_USERNAMES;

    /* qoS must be of acceptable level for the userName */
    /* reports do not have to match the level requested */
    if (pdu->command != REPORT_MSG &&
	(params->qoS & USEC_QOS_AUTHPRIV) < (session->qoS & USEC_QOS_AUTHPRIV))
	return USEC_STAT_UNSUPPORTED_QOS;

    if (params->qoS & USEC_QOS_AUTH) {
	memcpy(params->authDigestPtr, session->authKey, 16);
	md5Digest(pkt, pktlen, session->authKey, params->authDigestPtr);
	if (memcmp(params->authDigest, params->authDigestPtr, 16) != 0)
	    return USEC_STAT_WRONG_DIGEST_VALUES;

	if (params->agentBoots < session->agentBoots)
	    return USEC_STAT_NOT_IN_WINDOWS;

	if (params->agentBoots == session->agentBoots) {
	    int lower = session->agentClock + time(NULL) - SNMP_MESSAGE_LIFETIME;
	    if (lower < 0)
		lower = 0;
	    if (params->agentTime < lower)
		return USEC_STAT_NOT_IN_WINDOWS;
	}
	if (params->agentBoots > session->agentBoots
	    || params->agentTime > session->agentTime) {
	    /* update the LCD */
	    session->agentBoots = params->agentBoots;
	    session->agentTime = params->agentTime;
	    session->agentClock = params->agentTime - time(NULL);
	}
    }
    return 0;
}
