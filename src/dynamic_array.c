/*
 * $Id$
 *
 * DEBUG: section 0	Dynamic Arrays
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *   Squid is the result of efforts by numerous individuals from the
 *   Internet community.  Development is led by Duane Wessels of the
 *   National Laboratory for Applied Network Research and funded by
 *   the National Science Foundation.
 * 
 */
 
#ifdef HARVEST_COPYRIGHT
Copyright (c) 1994, 1995.  All rights reserved.
 
  The Harvest software was developed by the Internet Research Task
  Force Research Group on Resource Discovery (IRTF-RD):
 
        Mic Bowman of Transarc Corporation.
        Peter Danzig of the University of Southern California.
        Darren R. Hardy of the University of Colorado at Boulder.
        Udi Manber of the University of Arizona.
        Michael F. Schwartz of the University of Colorado at Boulder.
        Duane Wessels of the University of Colorado at Boulder.
 
  This copyright notice applies to software in the Harvest
  ``src/'' directory only.  Users should consult the individual
  copyright notices in the ``components/'' subdirectories for
  copyright information about other software bundled with the
  Harvest source code distribution.
 
TERMS OF USE
  
  The Harvest software may be used and re-distributed without
  charge, provided that the software origin and research team are
  cited in any use of the system.  Most commonly this is
  accomplished by including a link to the Harvest Home Page
  (http://harvest.cs.colorado.edu/) from the query page of any
  Broker you deploy, as well as in the query result pages.  These
  links are generated automatically by the standard Broker
  software distribution.
  
  The Harvest software is provided ``as is'', without express or
  implied warranty, and with no support nor obligation to assist
  in its use, correction, modification or enhancement.  We assume
  no liability with respect to the infringement of copyrights,
  trade secrets, or any patents, and are not responsible for
  consequential damages.  Proper use of the Harvest software is
  entirely the responsibility of the user.
 
DERIVATIVE WORKS
 
  Users may make derivative works from the Harvest software, subject 
  to the following constraints:
 
    - You must include the above copyright notice and these 
      accompanying paragraphs in all forms of derivative works, 
      and any documentation and other materials related to such 
      distribution and use acknowledge that the software was 
      developed at the above institutions.
 
    - You must notify IRTF-RD regarding your distribution of 
      the derivative work.
 
    - You must clearly notify users that your are distributing 
      a modified version and not the original Harvest software.
 
    - Any derivative product is also subject to these copyright 
      and use restrictions.
 
  Note that the Harvest software is NOT in the public domain.  We
  retain copyright, as specified above.
 
HISTORY OF FREE SOFTWARE STATUS
 
  Originally we required sites to license the software in cases
  where they were going to build commercial products/services
  around Harvest.  In June 1995 we changed this policy.  We now
  allow people to use the core Harvest software (the code found in
  the Harvest ``src/'' directory) for free.  We made this change
  in the interest of encouraging the widest possible deployment of
  the technology.  The Harvest software is really a reference
  implementation of a set of protocols and formats, some of which
  we intend to standardize.  We encourage commercial
  re-implementations of code complying to this set of standards.  
#endif

#include "squid.h"

/* return 0 for error */
dynamic_array *create_dynamic_array(size, delta)
     int size;
     int delta;
{
    dynamic_array *ary = NULL;

    ary = xcalloc(1, sizeof(dynamic_array));
    ary->collection = xcalloc(size, sizeof(void *));
    ary->size = size;
    ary->delta = delta;
    ary->index = 0;
    return (ary);
}

int insert_dynamic_array(ary, entry)
     dynamic_array *ary;
     void *entry;
{
    /* if run out of space,then increae array's size
     * by the amount of ary->delta
     */
    if (ary->index >= ary->size) {
	ary->size += ary->delta;
	ary->collection = xrealloc(ary->collection, ary->size * sizeof(void *));
    }
    ary->collection[(ary->index)++] = entry;
    return (ary->index);
}

/* keep the first new_size items of array */
int cut_dynamic_array(ary, new_size)
     dynamic_array *ary;
     unsigned int new_size;
{
    if (ary->index > new_size)
	ary->index = new_size;
    return (ary->index);
}

void destroy_dynamic_array(ary)
     dynamic_array *ary;
{
    safe_free(ary->collection);
    safe_free(ary);
}
