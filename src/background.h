/* A small package for cooperative background processing
 * This package polls functions until they return true.
 */

/* runInBackground(name,func,arg,done)
 * char *name;
 * int (*func)(char *name,void *arg)
 * void (*done)(char *name,void *arg)
 *
 * Add func to the list of background processes
 */
extern void runInBackground _PARAMS((char *name, int (*func) (void *), void *arg, void (*done) (void *)));

/* int doBackgroundProcessing()
 * Call one background processing function
 * returns true if there is more background processing to do
 */
extern int doBackgroundProcessing _PARAMS((void));
