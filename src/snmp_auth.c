/*
 * $Id$
 *
 * DEBUG: section 49     SNMP Interface
 * AUTHOR: Kostas Anagnostakis
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

/***********************************************************
        Copyright 1989 by Carnegie Mellon University

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

#include "squid.h"

void snmpAclCheckDone(int answer, void *);
static int snmpCommunityCheck(char *b, oid * name, int namelen);

void
snmpAclCheckStart(void *data)
{
    snmp_request_t * rq=(snmp_request_t *) data;
    communityEntry *cp;
    for (cp = Config.Snmp.communities; cp != NULL; cp = cp->next)
        if (!strcmp((char *) rq->community, cp->name) && cp->acls) {
            rq->acl_checklist = aclChecklistCreate(cp->acls,
                NULL, rq->from.sin_addr, NULL, NULL);
            aclNBCheck(rq->acl_checklist, snmpAclCheckDone, rq);
            return;
        }
    snmpAclCheckDone(ACCESS_ALLOWED, rq);
}

void
snmpAclCheckDone(int answer, void *data)
{
    snmp_request_t *rq = data;
    u_char *outbuf = rq->outbuf;

    struct snmp_pdu *PDU, *RespPDU;
    u_char *Community;
    variable_list *VarPtr;
    variable_list **VarPtrP;
    int ret;

    debug(49, 5) ("snmpAclCheckDone: %d\n", answer);
    rq->acl_checklist = NULL;
    PDU = rq->PDU;
    Community = rq->community;

    if (answer == ACCESS_DENIED) {
        debug(49, 3) ("snmpAclCheckDone: ACCESS DENIED (source)\n");
        snmpAgentParseDone(0, rq);
        return;
    }
    for (VarPtrP = &(PDU->variables);
        *VarPtrP;
        VarPtrP = &((*VarPtrP)->next_variable)) {
        VarPtr = *VarPtrP;

        /* access check for each variable */

        if (!snmpCommunityCheck((char *) Community, VarPtr->name, VarPtr->name_length)) {
            debug(49, 3) ("snmpAclCheckDone: ACCESS DENIED (requested oid).\n");
            snmpAgentParseDone(0, rq);
            return;
        }
    }
    debug(49, 7) ("snmpAclCheckDone: done checking communities.\n");
    Session->community = Community;
    Session->community_len = strlen((char *) Community);
    RespPDU = snmpAgentResponse(PDU);
    snmp_free_pdu(PDU);
    if (RespPDU == NULL) {
        debug(49, 5) ("snmpAclCheckDone: failed, might forward.\n");
        snmpAgentParseDone(2, rq);
        return;
    }
    debug(49, 6) ("snmpAclCheckDone: reqid=%u errstat=%d.\n",
        RespPDU->reqid,RespPDU->errstat);

    /* Encode it */
    ret = snmp_build(Session, RespPDU, outbuf, &rq->outlen);
    snmp_free_pdu(RespPDU);
    debug(49, 5) ("snmpAclCheckDone: ok ret=%d!\n",ret);
    snmpAgentParseDone(1, rq);
}

int
snmpViewCheck(oid * name, int namelen, int viewIndex)
{
    viewEntry *vwp, *savedvwp = NULL;

    debug(49, 8) ("snmpViewCheck: called with index=%d\n", viewIndex);
    for (vwp = Config.Snmp.views; vwp; vwp = vwp->next) {
        if (vwp->viewIndex != viewIndex)
            continue;
        debug(49, 7) ("snmpViewCheck: found view for subtree:\n");
        snmpDebugOid(7, vwp->viewSubtree, vwp->viewSubtreeLen);
        if (vwp->viewSubtreeLen > namelen
            || memcmp(vwp->viewSubtree, name, vwp->viewSubtreeLen * sizeof(oid)))
            continue;
        /* no wildcards here yet */
        if (!savedvwp) {
            savedvwp = vwp;
        } else {
            if (vwp->viewSubtreeLen > savedvwp->viewSubtreeLen)
                savedvwp = vwp;
        }
    }
    if (!savedvwp)
        return FALSE;
    if (savedvwp->viewType == VIEWINCLUDED)
        return TRUE;
    return FALSE;
}

static int
snmpCommunityCheck(char *b, oid * name, int namelen)
{
    communityEntry *cp;
    debug(49, 9) ("snmpCommunityCheck: %s against:\n", b);
    snmpDebugOid(9, name, namelen);
    for (cp = Config.Snmp.communities; cp; cp = cp->next)
        if (!strcmp(b, cp->name)) {
            return snmpViewCheck(name, namelen, cp->readView);
        }
    return 0;
}

int
snmpInitAgentAuth()
{
    Session = (struct snmp_session *) xmalloc(sizeof(struct snmp_session));
    Session->Version = SNMP_VERSION_1;
    Session->authenticator = NULL;
    Session->community = (u_char *) xstrdup("public");
    Session->community_len = 6;
    return 1;
}

