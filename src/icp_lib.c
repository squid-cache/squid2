
/* $Id$ */

/*
 * DEBUG: Section 13          icp_lib
 */

#include "squid.h"



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
	debug(13, 1, "icp_libReadDataBegin - error reading DATABEG header\n");
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

	debug(13, 4, "ReadDataBegin - reading data size = %d\n", to_read);

	while (to_read) {
	    if ((len = read(sock, p, to_read)) < 0) {
		debug(13, 1, "ReadDataBegin - error reading data: %s\n",
		    xstrerror());
		result = COMM_ERROR;
	    } else {
		debug(13, 4, "ReadDataBegin - read  %d bytes\n", len);
		to_read -= len;
		p += len;
		result = COMM_OK;
	    }
	}
	debug(13, 4, "ReadDataBegin - total %d bytes read\n", p - buf);
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

    debug(13, 3, "ReadData\n");
    if ((len = read(sock, (char *) &tmp, sizeof(u_num32))) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(13, 1, "ReadData - error reading DATA header\n");
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
		debug(13, 1, "ReadData - error reading data\n");
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

    debug(13, 1, "ReadError\n");

    if ((len = read(sock, (char *) &code, sizeof(unsigned short))) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(13, 1, "ReadError - error reading error code\n");
    } else if ((len = read(sock, (char *) buf, buf_len)) <= 0) {
	/* Return error; assume zero bytes read is closed connection. */
	debug(13, 1, "ReadError - error reading error message\n");
    } else {
	debug(13, 1, "ReadError - msg: %s\n", buf);
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
	    debug(13, 1, "icp_receive_data - error reading header\n");
	    result = COMM_ERROR;	/* Will cause HandleRead to close conn. */
	} else {
	    int op = ntohs(msg->header.opcode);
	    /* Process request. */
	    if (op == ICP_OP_DATABEG) {
		debug(13, 1, "icp_receive_data - processing ICP_OP_DATABEG\n");
		result = ReadDataBegin(sock, msg);
	    } else if (op == ICP_OP_DATA) {
		debug(13, 1, "icp_receive_data - processing ICP_OP_DATA\n");
		result = ReadData(sock, msg);
	    } else if (op == ICP_OP_DATAEND) {
		debug(13, 1, "icp_receive_data - processing ICP_OP_DATAEND\n");
		result = ReadData(sock, msg);
		done = 1;
	    } else if (op == ICP_OP_ERR) {
		debug(13, 1, "icp_receive_data - processing ICP_OP_ERR\n");
		ReadError(sock, msg);
		done = 1;
	    } else {
		/* Should not be any other opcode. */
		debug(13, 1, "icp_receive_data - invalid opcode recieved: %d\n", op);
	    }
/*      if (msg->offset == msg->object_size) done = 1; */
	}
    }
    return result;
}
