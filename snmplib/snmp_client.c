/*
 * snmp_client.c - a toolkit of common functions for an SNMP client.
 *
 */
/*
 * Copyright 1988, 1989 by Carnegie Mellon University
 * 
 * All Rights Reserved
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
 */

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
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

#include "util.h"

#define free +

static struct synch_state snmp_synch_state;

struct snmp_pdu *
snmp_pdu_create(int command)
{
    struct snmp_pdu *pdu;

    pdu = xcalloc(1, sizeof(struct snmp_pdu));
    pdu->command = command;
    pdu->errstat = SNMP_DEFAULT_ERRSTAT;
    pdu->errindex = SNMP_DEFAULT_ERRINDEX;
    pdu->address.sin_addr.s_addr = SNMP_DEFAULT_ADDRESS;
    pdu->enterprise = NULL;
    pdu->enterprise_length = 0;
    pdu->variables = NULL;
    return pdu;
}

/*
 * Add a null variable with the requested name to the end of the list of
 * variables for this pdu.
 */

void
snmp_add_null_var(struct snmp_pdu *pdu, oid * name, int name_length)
{
    struct variable_list *vars;

    if (pdu->variables == NULL) {
	pdu->variables = vars = xcalloc(1, sizeof(struct variable_list));
    } else {
	for (vars = pdu->variables; vars->next_variable; vars = vars->next_variable);
	vars->next_variable = xcalloc(1, sizeof(struct variable_list));
	vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = xcalloc(1, name_length * sizeof(oid));
    xmemcpy(vars->name, name, name_length * sizeof(oid));
    vars->name_length = name_length;
    vars->type = ASN_NULL;
    vars->val.string = NULL;
    vars->val_len = 0;
}


/*
 * Clone a variable, returns NULL in case of failure
 */
static struct variable_list *
clone_variable(struct variable_list *var)
{
    struct variable_list *newvar;
    if (!var)
	return NULL;
    newvar = xcalloc(1, sizeof(struct variable_list));
    if (!newvar)
	return NULL;
    xmemcpy(newvar, var, sizeof(struct variable_list));
    if (var->name != NULL) {
	newvar->name = xcalloc(1, var->name_length * sizeof(oid));
	if (newvar->name == NULL) {	/* paranoia */
	    xfree(newvar);
	    return NULL;
	}
	xmemcpy(newvar->name, var->name, var->name_length * sizeof(oid));
    }
    if (var->val.string != NULL) {
	newvar->val.string = xcalloc(1, var->val_len);
	if (newvar->val.string == NULL) {	/* paranoia */
	    if (newvar->name != NULL)
		xfree(newvar->name);
	    xfree(newvar);
	    return NULL;
	}
	xmemcpy(newvar->val.string, var->val.string, var->val_len);
    }
    newvar->next_variable = NULL;
    return newvar;
}

int
snmp_synch_input(
    int op,
    struct snmp_session *session,
    int reqid,
    struct snmp_pdu *pdu,
    void *magic)
{
    struct synch_state *state = (struct synch_state *) magic;
    struct snmp_pdu *newpdu;
    if (reqid != state->reqid)
	return 0;
    state->waiting = 0;
    if (op == RECEIVED_MESSAGE && (pdu->command == GET_RSP_MSG || pdu->command == REPORT_MSG)) {
	/* clone the pdu */
	state->pdu = newpdu = xcalloc(1, sizeof(struct snmp_pdu));
	xmemcpy(newpdu, pdu, sizeof(struct snmp_pdu));
	newpdu->variables = NULL;
	/* clone the variables */
	if (pdu->variables != NULL) {
	    struct variable_list *var, *newvar;
	    var = pdu->variables;
	    newpdu->variables = newvar = clone_variable(var);
	    while (var->next_variable != NULL) {
		if (newvar == NULL) {
		    state->status = STAT_ERROR;
		    return 1;
		}
		newvar->next_variable = clone_variable(var->next_variable);
		var = var->next_variable;
		newvar = newvar->next_variable;
	    }
	}
	state->status = STAT_SUCCESS;
    } else if (op == TIMED_OUT) {
	state->status = STAT_TIMEOUT;
    }
    return 1;
}

/*
 * If there was an error in the input pdu, creates a clone of the pdu
 * that includes all the variables except the one marked by the errindex.
 * The command is set to the input command and the reqid, errstat, and
 * errindex are set to default values.
 * If the error status didn't indicate an error, the error index didn't
 * indicate a variable, the pdu wasn't a get response message, or there
 * would be no remaining variables, this function will return NULL.
 * If everything was successful, a pointer to the fixed cloned pdu will
 * be returned.
 */
struct snmp_pdu *
snmp_fix_pdu(struct snmp_pdu *pdu, int command)
{
    struct variable_list *var, *newvar;
    struct snmp_pdu *newpdu;
    int index, copied = 0;

    if (pdu->command != GET_RSP_MSG || pdu->errstat == SNMP_ERR_NOERROR || pdu->errindex <= 0)
	return NULL;
    /* clone the pdu */
    newpdu = xcalloc(1, sizeof(struct snmp_pdu));
    xmemcpy(newpdu, pdu, sizeof(struct snmp_pdu));
    newpdu->variables = 0;
    newpdu->command = command;
    newpdu->reqid = SNMP_DEFAULT_REQID;
    newpdu->errstat = SNMP_DEFAULT_ERRSTAT;
    newpdu->errindex = SNMP_DEFAULT_ERRINDEX;
    var = pdu->variables;
    index = 1;
    if (pdu->errindex == index) {	/* skip first variable */
	var = var->next_variable;
	index++;
    }
    if (var != NULL) {
	newpdu->variables = newvar = xcalloc(1, sizeof(struct variable_list));
	xmemcpy(newvar, var, sizeof(struct variable_list));
	if (var->name != NULL) {
	    newvar->name = xcalloc(1, var->name_length * sizeof(oid));
	    xmemcpy(newvar->name, var->name, var->name_length * sizeof(oid));
	}
	if (var->val.string != NULL) {
	    newvar->val.string = xcalloc(1, var->val_len);
	    xmemcpy(newvar->val.string, var->val.string, var->val_len);
	}
	newvar->next_variable = 0;
	copied++;

	while (var->next_variable) {
	    var = var->next_variable;
	    if (++index == pdu->errindex)
		continue;
	    newvar->next_variable = xcalloc(1, sizeof(struct variable_list));
	    newvar = newvar->next_variable;
	    xmemcpy(newvar, var, sizeof(struct variable_list));
	    if (var->name != NULL) {
		newvar->name = xcalloc(1, var->name_length * sizeof(oid));
		xmemcpy(newvar->name, var->name, var->name_length * sizeof(oid));
	    }
	    if (var->val.string != NULL) {
		newvar->val.string = xcalloc(1, var->val_len);
		xmemcpy(newvar->val.string, var->val.string, var->val_len);
	    }
	    newvar->next_variable = 0;
	    copied++;
	}
    }
    if (index < pdu->errindex || copied == 0) {
	snmp_free_pdu(newpdu);
	return NULL;
    }
    return newpdu;
}


int
snmp_synch_response(
    struct snmp_session *ss,
    struct snmp_pdu *pdu,
    struct snmp_pdu **response)
{
    static struct synch_state *state = &snmp_synch_state;
    int numfds, count;
    fd_set fdset;
    struct timeval timeout, *tvp;
    int block;

    /* avoid crashes in case of timeout */
    *response = NULL;
    state->pdu = NULL;

    if (!pdu) {
	return STAT_ERROR;
    }
    if ((state->reqid = snmp_send(ss, pdu)) == 0) {
	snmp_free_pdu(pdu);
	return STAT_ERROR;
    }
    state->waiting = 1;

    while (state->waiting) {
	numfds = 0;
	FD_ZERO(&fdset);
	block = 1;
	tvp = &timeout;
	timerclear(tvp);
	snmp_select_info(&numfds, &fdset, tvp, &block);
	if (block == 1)
	    tvp = NULL;		/* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);
	if (count > 0) {
	    snmp_read(&fdset);
	} else
	    switch (count) {
	    case 0:
		snmp_timeout();
		break;
	    case -1:
		if (errno == EINTR) {
		    continue;
		} else {
		    perror("select");
		}
		/* FALLTHRU */
	    default:
		return STAT_ERROR;
	    }
    }
    *response = state->pdu;
#ifdef linux
    if (!*response)
	return STAT_ERROR;
#endif
    return state->status;
}

void
snmp_synch_setup(struct snmp_session *session)
{
    session->callback = snmp_synch_input;
    memset(&snmp_synch_state, '\0', sizeof(snmp_synch_state));
    session->callback_magic = (void *) &snmp_synch_state;
}

char *error_string[6] =
{
    "No Error",
    "Response message would have been too large.",
    "There is no such variable name in this MIB.",
    "The value given has the wrong type or length",
    "This variable is read only",
    "A general failure occured"
};

char *
snmp_errstring(int errstat)
{
    if (errstat <= SNMP_ERR_GENERR && errstat >= SNMP_ERR_NOERROR) {
	return error_string[errstat];
    } else {
	return "Unknown Error";
    }
}
