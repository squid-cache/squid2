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

#ifndef _HTTP_BODY_H_
#define _HTTP_BODY_H_

/*
 * Note: Body is used only for messages with a small text content that is known a
 * priory (e.g., error messages).
 */

struct _HttpBody {
    /* private, never dereference these */
    char *buf;      /* null terminating _text_ buffer, not for binary stuff */
    FREE *freefunc; /* used to free() .buf */
    int size;
};

typedef struct _HttpBody HttpBody;

/* init/clean */
extern void httpBodyInit(HttpBody *body);
extern void httpBodyClean(HttpBody *body);

/* get body ptr (always use this) */
extern const char *httpBodyPtr(const HttpBody *body);

/* set body, if freefunc is NULL the content will be copied, otherwise not */
extern void httpBodySet(HttpBody *body, const char *content, int size, FREE *freefunc);

/* pack */
extern void httpBodyPackInto(const HttpBody *body, Packer *p);


#endif /* ifndef _HTTP_REPLY_H_ */
