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

#ifndef _HTTP_STATUS_LINE_H_
#define _HTTP_STATUS_LINE_H_

/* status line */
struct _HttpStatusLine {
    /* public, read only */
    double version;
    const char *reason; /* points to a _constant_ string (default or supplied), never free()d */
    http_status status;
};

typedef struct _HttpStatusLine HttpStatusLine;

/* init/clean */
extern void httpStatusLineInit(HttpStatusLine *sline);
extern void httpStatusLineClean(HttpStatusLine *sline);

/* set values */
extern void httpStatusLineSet(HttpStatusLine *sline, double version, http_status status, const char *reason);

/* parse/pack */
/* parse a 0-terminating buffer and fill internal structires; returns true if successful */
extern int httpStatusLineParse(HttpStatusLine *sline, const char *start, const char *end);
/* pack fields using Packer */
extern void httpStatusLinePackInto(const HttpStatusLine *sline, Packer *p);

#endif /* ifndef _HTTP_STATUS_LINE_H_ */
