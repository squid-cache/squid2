/**********************************************************************
 *
 *           Copyright 1997 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 * $Id$
 * 
 **********************************************************************/

/* Our autoconf variables */
#include "config.h"

#include <stdio.h>

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
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#if HAVE_ERRNO_H
#include <errno.h>
#endif

#include "asn1.h"
#include "snmp_error.h"
#include "snmp_pdu.h"
#include "snmp_vars.h"

#include "snmp_session.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_api_error.h"

/* Define these here, as they aren't defined normall under
 * cygnus Win32 stuff.
 */
#undef timerclear
#define timerclear(tvp) (tvp)->tv_sec = (tvp)->tv_usec = 0

/* #define DEBUG_CLIENT 1 */

int snmp_synch_input(int Operation, 
		     struct snmp_session *Session, 
		     int RequestID, 
		     struct snmp_pdu *pdu,
		     void *magic)
{
  struct variable_list *var;
  struct synch_state *state = (struct synch_state *)magic;
  struct snmp_pdu *newpdu;

  struct variable_list *varPtr;

#ifdef DEBUG_CLIENT
  printf("CLIENT %x: Synchronizing input.\n", (unsigned int)pdu);
#endif

  /* Make sure this is the proper request
   */
  if (RequestID != state->reqid)
    return 0;
  state->waiting = 0;

  /* Did we receive a Get Response
   */
  if (Operation == RECEIVED_MESSAGE && pdu->command == SNMP_PDU_RESPONSE) {

    /* clone the pdu */
    state->pdu = newpdu = snmp_pdu_clone(pdu);
    newpdu->variables = 0;

    /* Clone all variables */
    var = pdu->variables;
    if (var != NULL) {
      newpdu->variables = snmp_var_clone(var);

      varPtr = newpdu->variables;

      /* While there are more variables */
      while(var->next_variable) {

	/* Clone the next one */
	varPtr->next_variable = snmp_var_clone(var->next_variable);

	/* And move on */
	var    = var->next_variable;
	varPtr = varPtr->next_variable;

      }
      varPtr->next_variable = NULL;
    }
    state->status = STAT_SUCCESS;
  } else if (Operation == TIMED_OUT) {
    state->status = STAT_TIMEOUT;
  }
  return 1;
}

struct synch_state snmp_synch_state;

int snmp_synch_response(struct snmp_session *Session, 
			struct snmp_pdu *PDU,
			struct snmp_pdu **ResponsePDUP)
{
  struct synch_state *state = &snmp_synch_state;
  int numfds, count;
  fd_set fdset;
  struct timeval timeout, *tvp;
  int block;

  state->reqid = snmp_send(Session, PDU);
  if (state->reqid == 0) {
    *ResponsePDUP = NULL;
    snmp_free_pdu(PDU);
    return STAT_ERROR;
  }
  state->waiting = 1;

  while(state->waiting) {
    numfds = 0;
    FD_ZERO(&fdset);
    block = 1;
    tvp = &timeout;
    timerclear(tvp);
    snmp_select_info(&numfds, &fdset, tvp, &block);
    if (block == 1)
      tvp = NULL;	/* block without timeout */
    count = select(numfds, &fdset, 0, 0, tvp);
    if (count > 0){
      snmp_read(&fdset);
    } else switch(count){
    case 0:
      snmp_timeout();
      break;
    case -1:
      if (errno == EINTR){
	continue;
      } else {
	perror("select");
      }
      /* FALLTHRU */
    default:
      return STAT_ERROR;
    }
  }
  *ResponsePDUP = state->pdu;
  return state->status;
}

void snmp_synch_setup(struct snmp_session *Session)
{
  Session->callback = snmp_synch_input;
  Session->callback_magic = (void *)&snmp_synch_state;
}
