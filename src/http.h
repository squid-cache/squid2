
/*
 * $Id$
 *
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#ifndef HTTP_H
#define HTTP_H

#define HTTP_REPLY_FIELD_SZ 128

struct _http_reply {
    double version;
    int code;
    int content_length;
    int hdr_sz;
    int cache_control;
    int misc_headers;
    time_t date;
    time_t expires;
    time_t last_modified;
    char content_type[HTTP_REPLY_FIELD_SZ];
    char user_agent[HTTP_REPLY_FIELD_SZ << 2];
};

#define BUF_TYPE_8K 	1
#define BUF_TYPE_MALLOC 2

typedef struct {
    StoreEntry *entry;
    request_t *request;
    char *req_hdr;
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
    char *reply_hdr;
    int req_hdr_sz;
    int reply_hdr_state;
    peer *neighbor;		/* neighbor request made to */
    int eof;			/* reached end-of-object? */
    request_t *orig_request;
} HttpStateData;

extern int httpCachable _PARAMS((method_t));
extern int proxyhttpStart _PARAMS((request_t *, StoreEntry *, peer *));
extern int httpStart _PARAMS((request_t *, char *, int, StoreEntry *));
extern void httpParseReplyHeaders _PARAMS((const char *, struct _http_reply *));
extern void httpProcessReplyHeader _PARAMS((HttpStateData *, const char *, int));
extern void httpReplyHeaderStats _PARAMS((StoreEntry *));
extern size_t httpBuildRequestHeader _PARAMS((request_t * request,
	request_t * orig_request,
	StoreEntry * entry,
	char *hdr_in,
	size_t * in_len,
	char *hdr_out,
	size_t out_sz,
	int cfd));

#define ANONYMIZER_NONE		0
#define ANONYMIZER_STANDARD	1
#define ANONYMIZER_PARANOID	2

#endif /* HTTP_H */
