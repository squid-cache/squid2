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

#ifndef _HTTP_HEADER_H_
#define _HTTP_HEADER_H_

#if 0
struct _HttpHeaderField {
	char *name;   /* field-name  from HTTP/1.1 (no column after name!) */
	char *value;  /* field-value from HTTP/1.1 */
};
#endif

/* recognized or "known" header fields; @?@ add more! */
typedef enum {
    HDR_ACCEPT,
    HDR_AGE,
    HDR_CACHE_CONTROL,
    HDR_CONNECTION,
    HDR_CONTENT_ENCODING,
    HDR_CONTENT_LENGTH,
    HDR_CONTENT_MD5,
    HDR_CONTENT_TYPE,
    HDR_DATE,
    HDR_ETAG,
    HDR_EXPIRES,
    HDR_HOST,
    HDR_IMS,
    HDR_LAST_MODIFIED,
    HDR_LOCATION,
    HDR_MAX_FORWARDS,
    HDR_PROXY_AUTHENTICATE,
    HDR_PUBLIC,
    HDR_RETRY_AFTER,
    HDR_SET_COOKIE,
    HDR_UPGRADE,
    HDR_WARNING,
    HDR_WWW_AUTHENTICATE,
    HDR_PROXY_KEEPALIVE,
    HDR_OTHER,
    HDR_ENUM_END
} http_hdr_type;

/* server cache control */
struct _HttpScc {
    int mask;
    time_t max_age;
};
typedef struct _HttpScc HttpScc;

/* server cache control */
typedef enum {
    SCC_PUBLIC,
    SCC_PRIVATE,
    SCC_NO_CACHE,
    SCC_NO_STORE,
    SCC_NO_TRANSFORM,
    SCC_MUST_REVALIDATE,
    SCC_PROXY_REVALIDATE,
    SCC_MAX_AGE,
    SCC_OTHER,
    SCC_ENUM_END
} http_scc_type;

typedef struct _HttpHeaderExtField HttpHeaderExtField;

/* a storage for an entry of one of possible types (for lower level routines) */
union _field_store {
    int v_int;
    time_t v_time;
    char *v_pchar;
    const char *v_pcchar;
    HttpScc *v_pscc;
    HttpHeaderExtField *v_pefield;
};

typedef union _field_store field_store;

typedef struct _HttpHeaderEntry HttpHeaderEntry;

struct _HttpHeader {
    /* public, read only */
    int emask;           /* bits set for present entries */

    /* protected, do not use these, use interface functions instead */
    int capacity;        /* max #entries before we have to grow */
    int ucount;          /* #entries used, including holes */
    HttpHeaderEntry *entries;
};


typedef struct _HttpHeader HttpHeader;

/* module initialization to be called from main() */
extern void httpHeaderInitModule();

/* create/init/clean/destroy */
extern HttpHeader *httpHeaderCreate();
extern void httpHeaderInit(HttpHeader *hdr);
extern void httpHeaderClean(HttpHeader *hdr);
extern void httpHeaderDestroy(HttpHeader *hdr);

/* clone: creates new header and copies all entries one-by-one */
HttpHeader *httpHeaderClone(HttpHeader *hdr);

/* parse/pack */
/* parse a 0-terminating buffer and fill internal structires; _end points at the first character after the header; returns true if successfull */
extern int httpHeaderParse(HttpHeader *hdr, const char *header_start, const char *header_end);
/* pack header using packer */
extern void httpHeaderPackInto(const HttpHeader *hdr, Packer *p);

/* test if a field is present */
extern int httpHeaderHas(const HttpHeader *hdr, http_hdr_type type);

/* delete a field if any (same as setting an exising field to an invalid value) */
extern void httpHeaderDel(HttpHeader *hdr, http_hdr_type id);

/*
 * set a field 
 * If field is not present, it is added; otherwise, old content is destroyed.
 * The function will duplicate the value submitted so it is safe to pass tmp values.
 * Note: in most cases it is much better to use higher level
 * routines provided by HttpReply and HttpRequest
 */
extern void httpHeaderSetInt(HttpHeader *hdr, http_hdr_type type, int number);
extern void httpHeaderSetTime(HttpHeader *hdr, http_hdr_type type, time_t time);
extern void httpHeaderSetStr(HttpHeader *hdr, http_hdr_type type, const char *str);

/* add extension header (these fields are not parsed/analyzed/joined, etc.) */
extern void httpHeaderAddExt(HttpHeader *hdr, const char *name, const char* value);

/*
 * get a value of a field (not lvalue though; we could change this to return
 * lvalues, but it creates more problems than it solves)
 */
extern field_store httpHeaderGet(const HttpHeader *hdr, http_hdr_type id);
extern const char *httpHeaderGetStr(const HttpHeader *hdr, http_hdr_type id);
extern time_t httpHeaderGetTime(const HttpHeader *hdr, http_hdr_type id);
extern HttpScc *httpHeaderGetScc(const HttpHeader *hdr);

/*
 * Note: there is no way to get a value of an extention field; extention field
 * is something you do not know anything about so it does not make sense to ask
 * for it.
 */

/*
 * deletes all field(s) with a given name if any, returns #fields deleted;
 * used to process Connection: header and delete fields in "paranoid" setup
 */
int httpHeaderDelFields(HttpHeader *hdr, const char *name);



/* pack report about current header usage and other stats */
extern void httpHeaderStoreReport(StoreEntry *e);
extern void httpHeaderStoreReqReport(StoreEntry *e);
extern void httpHeaderStoreRepReport(StoreEntry *e);


#endif /* ndef _HTTP_HEADER_H_ */
