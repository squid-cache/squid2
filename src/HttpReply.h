/*
 * $Id$
 *
 * AUTHOR: Alex Rousskov
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

#ifndef _HTTP_REPLY_H_
#define _HTTP_REPLY_H_

#include "HttpStatusLine.h"
#include "HttpHeader.h"
#include "HttpBody.h"

/* tmp hack @?@ delete it */
#ifndef Const
#define Const const
#endif

/* parse state */
typedef enum { psReadyToParseStartLine = 0, psReadyToParseHeaders, psParsed, psError } HttpMsgParseState;


struct _HttpReply {
    /* unsupported, writable, may disappear/change in the future */
    Const int hdr_sz;   /* sums _stored_ status-line, headers, and <CRLF> */

    /* public, readable */
    Const HttpMsgParseState pstate; /* the current parsing state */

    /* public, writable, but use interfaces below when possible */
    HttpStatusLine sline;
    HttpHeader hdr;
    HttpBody body;  /* used for small constant memory-resident text bodies only */
};

typedef struct _HttpReply HttpReply;

/* create/init/clean/destroy */
extern HttpReply *httpReplyCreate();
extern void httpReplyInit(HttpReply *rep);
extern void httpReplyClean(HttpReply *rep);
extern void httpReplyDestroy(HttpReply *rep);

/* reset: clean, then init */
void httpReplyReset(HttpReply *rep);

/* parse/pack */
/* parse returns -1,0,+1 on error,need-more-data,success */
extern int httpReplyParse(HttpReply *rep, const char *buf); /*, int atEnd); */
extern void httpReplyPackInto(const HttpReply *rep, Packer *p);

/* ez-routines */

/* mem-pack: returns a ready to use mem buffer with a packed reply */
extern MemBuf httpReplyPack(const HttpReply *rep);

/* swap: create swap-based packer, pack, destroy packer */
extern void httpReplySwapOut(const HttpReply *rep, StoreEntry *e);

/* set commonly used info with one call */
extern void httpReplySetHeaders(HttpReply *rep, double ver, http_status status,
    const char *reason, const char *ctype, int clen, time_t lmt, time_t expires);


/* do everything in one call: init, set, pack, clean, return MemBuf */
extern MemBuf httpPackedReply(double ver, http_status status, const char *ctype, 
    int clen, time_t lmt, time_t expires);

/* construct 304 reply and pack it into MemBuf, return MemBuf */
extern MemBuf httpPacked304Reply(const HttpReply *rep);

/*
 * header manipulation 
 *
 * never go to header directly if you can use these:
 *
 * our interpretation of headers often changes and you may get into trouble
 *    if you, for example, assume that HDR_EXPIRES contains expire info
 *
 * if you think about it, in most cases, you are not looking for the information
 *    in the header, but rather for current state of the reply, which may or maynot
 *    depend on headers. 
 *
 * For example, the _real_ question is
 *        "when does this object expire?" 
 *     not 
 *        "what is the value of the 'Expires:' header?"
 */

/* update when 304 reply is received for a cached object */
extern void httpReplyUpdateOnNotModified(HttpReply *rep, HttpReply *freshRep);

extern int httpReplyContentLen(const HttpReply *rep);
extern const char *httpReplyContentType(const HttpReply *rep);
extern time_t httpReplyExpires(const HttpReply *rep);
extern int httpReplyHasScc(const HttpReply *rep, http_scc_type type);

#endif /* ifndef _HTTP_REPLY_H_ */
