/* A small package for cooperative background processing
 * This package polls functions until they return true.
 */

#include "squid.h"

/* The list of background processes */
struct bg_entry {
    int (*func) _PARAMS((void *arg));
    void (*done) _PARAMS((void *arg));
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
void runInBackground(name, func, arg, done)
     char *name;
     int (*func) _PARAMS((void *arg));
     void *arg;
     void (*done) _PARAMS((void *arg));
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
extern int doBackgroundProcessing()
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
