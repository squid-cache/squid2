static char rcsid[] = "$Id$";
/* 
 *  File:         icp_lib.c
 *  Description:  library of icp send functions.
 *  Author:       John Noll, USC
 *  Created:      Wed Mar 30 18:12:01 1994
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "debug.h"
#include "icp_lib.h"
#include "comm.h"
#include "proto.h"
#include "util.h"

/* Send a QUERY request to server  */
int icp_query(sock, reqnum, auth, rid, url, hostname, port)
     int sock;
     u_num32 reqnum;
     u_num32 *auth;
     struct in_addr rid;
     char *url;
     char *hostname;
     int port;
{
    char *buf, *p;
    int len;
    u_num32 myAddress;
    icp_common_t header;

    len = sizeof(icp_common_t) + sizeof(struct in_addr) + strlen(url) + 1;
    buf = (char *) xcalloc(1, len);

    memset(&header, '\0', sizeof(icp_common_t));
    header.opcode = htons(ICP_OP_QUERY);
    header.length = htons(len);
    p = buf;
    memcpy(p, &header, sizeof(header));
    p += sizeof(header);
    myAddress = htonl(rid.s_addr);
    memcpy(p, &myAddress, sizeof(struct in_addr));
    p += sizeof(struct in_addr);
    memcpy(p, url, strlen(url));	/* already zero filled by calloc */
    return comm_udp_send(sock, hostname, port, buf, header.length);
}

/* Send a SEND object request over SOCK. */
int icp_send(sock, reqnum, auth, rid, url)
     int sock;
     u_num32 reqnum;
     u_num32 *auth;
     struct in_addr rid;
     char *url;
{
    icp_common_t header;
    int len = sizeof(icp_common_t) + sizeof(struct in_addr) + strlen(url) + 1;
    char *p, *buf;

    buf = (char *) xcalloc(1, len);
    memset(&header, '\0', sizeof(icp_common_t));
    header.opcode = htons(ICP_OP_SEND);
    header.length = htons(len);
    p = buf;
    memcpy(p, &header, sizeof(icp_common_t));
    p += sizeof(icp_common_t);
    memcpy(p, &rid, sizeof(struct in_addr));
    p += sizeof(struct in_addr);
    memcpy(p, url, strlen(url));	/* already zero filled by xcalloc */

    write(sock, buf, len);
    return 0;
}

static int ReadDataBegin(sock, msg)
     int sock;
     icp_object *msg;
{
    int len, result = COMM_OK;
    icp_datab_t tmp;

    if ((len = read(sock, (char *) &tmp, 3 * sizeof(u_num32))) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(1, "icp_libReadDataBegin - error reading DATABEG header\n");
	result = COMM_ERROR;
    } else {
	char *buf, *p;
	int to_read;

	msg->ttl = ntohl(tmp.db_ttl);
	msg->timestamp = ntohl(tmp.db_ts);
	msg->object_size = ntohl(tmp.db_size);

	if (msg->object_size) {
	    msg->buf_len = msg->object_size;
	} else {
	    msg->buf_len = msg->header.length;
	}

	buf = (char *) xcalloc(1, msg->buf_len);
	to_read = (msg->header.length - sizeof(icp_common_t) -
	    3 * sizeof(u_num32));
	p = buf;

	debug(4, "ReadDataBegin - reading data size = %d\n", to_read);

	while (to_read) {
	    if ((len = read(sock, p, to_read)) < 0) {
		debug(1, "ReadDataBegin - error reading data: %s\n",
		    xstrerror());
		result = COMM_ERROR;
	    } else {
		debug(4, "ReadDataBegin - read  %d bytes\n", len);
		to_read -= len;
		p += len;
		result = COMM_OK;
	    }
	}
	debug(4, "ReadDataBegin - total %d bytes read\n", p - buf);
	msg->data = buf;
	msg->offset += p - buf;
    }
    return result;
}

static int ReadData(sock, msg)
     int sock;
     icp_object *msg;
{
    int result = COMM_OK, len;
    u_num32 tmp;

    debug(3, "ReadData\n");
    if ((len = read(sock, (char *) &tmp, sizeof(u_num32))) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(1, "ReadData - error reading DATA header\n");
	result = COMM_ERROR;
    } else {
	int msg_len = (msg->header.length - sizeof(icp_common_t)
	    - sizeof(u_num32));
	if (msg->buf_len < (msg->offset + msg_len)) {
	    msg->buf_len += msg_len;
	    msg->data = (char *) xrealloc(msg->data, msg->buf_len);
	}
	while (msg_len) {
	    if ((len = read(sock, msg->data + msg->offset, msg_len)) < 0) {
		/* Return error; assume zero bytes read is closed connection. */
		debug(1, "ReadData - error reading data\n");
		result = COMM_ERROR;
	    } else {
		msg->offset += len;
		msg_len -= len;
	    }
	}
    }
    return result;
}


static void ReadError(sock, msg)
     int sock;
     icp_object *msg;
{
    int len, buf_len = (msg->header.length - sizeof(icp_common_t)
	- sizeof(unsigned short) + 1);
    unsigned short code;
    char *buf = (char *) xcalloc(1, buf_len);

    debug(1, "ReadError\n");

    if ((len = read(sock, (char *) &code, sizeof(unsigned short))) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(1, "ReadError - error reading error code\n");
    } else if ((len = read(sock, (char *) buf, buf_len)) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(1, "ReadError - error reading error message\n");
    } else {
	debug(1, "ReadError - msg: %s\n", buf);
	msg->data = buf;
    }
}

int icp_receive_data(sock, msg)
     int sock;
     icp_object *msg;
{
    int result = COMM_OK, done = 0, len;

    while (!done && !result) {
	if ((len = read(sock, (char *) &msg->header, sizeof(icp_common_t))) <= 0) {
	    /* Return error; assume zero bytes read is closed connection. */
	    debug(1, "icp_receive_data - error reading header\n");
	    result = COMM_ERROR;	/* Will cause HandleRead to close conn. */
	} else {
	    int op = ntohs(msg->header.opcode);
	    /* Process request. */
	    if (op == ICP_OP_DATABEG) {
		debug(1, "icp_receive_data - processing ICP_OP_DATABEG\n");
		result = ReadDataBegin(sock, msg);
	    } else if (op == ICP_OP_DATA) {
		debug(1, "icp_receive_data - processing ICP_OP_DATA\n");
		result = ReadData(sock, msg);
	    } else if (op == ICP_OP_DATAEND) {
		debug(1, "icp_receive_data - processing ICP_OP_DATAEND\n");
		result = ReadData(sock, msg);
		done = 1;
	    } else if (op == ICP_OP_ERR) {
		debug(1, "icp_receive_data - processing ICP_OP_ERR\n");
		ReadError(sock, msg);
		done = 1;
	    } else {
		/* Should not be any other opcode. */
		debug(1, "icp_receive_data - invalid opcode recieved: %d\n", op);
	    }
/*      if (msg->offset == msg->object_size) done = 1; */
	}
    }
    return result;
}
