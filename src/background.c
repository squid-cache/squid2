
/*
 * $Id$
 *
 * DEBUG: Section 0     Background Processing
 * AUTHOR: Henrik Nordstrom
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#include "squid.h"

/* The list of background processes */
struct bg_entry {
    int (*func) (void *arg);
    void (*done) (void *arg);
    void *arg;
    char *name;
    struct bg_entry *next;
};

static struct bg_entry *tasks = NULL;

/* Last called process */
static struct bg_entry *last_called = NULL;

/* runInBackground(func,arg)
 * int (*func)(void *arg)
 *
 * Add a function to the list of background processes
 * doBackgroundProcessing calls func until func returns true
 * when func returns true, done is called.
 */
void
runInBackground(char *name,
	int (*func) (void *arg),
	void *arg,
	void (*done) (void *arg))
{
    struct bg_entry *entry = NULL;

    entry = xcalloc(1, sizeof(*entry));
    entry->func = func;
    entry->arg = arg;
    entry->name = name;
    entry->done = done;
    entry->next = tasks;
    tasks = entry;
}


/* int doBackgroundProcessing()
 * Call one background processing function
 * returns true if there is more background processing to do
 */
extern int
doBackgroundProcessing()
{
    struct bg_entry *this = NULL;

    if (!tasks) {
	last_called = NULL;
	return 0;
    }
    if (last_called && last_called->next) {
	this = last_called->next;
    } else {
	this = tasks;
	last_called = NULL;
    }

    if (this->func(this->arg)) {
	/* Call this again later */
	/* Remember that this one is called, to call the next one
	 * on next call */
	last_called = this;
    } else {
	/* We are done */
	if (this->done)
	    this->done(this->arg);
	/* Delete this entry */
	if (last_called)
	    last_called->next = this->next;
	else
	    tasks = this->next;
	safe_free(this);
    }
    return tasks ? 1 : 0;
}
