static char rcsid[] = "$Id$";
/*---------------------------------------------------------------------------
--
--  stack.c - Functions to handle a stack of pointers 
-- 
--  This file contains the following functions:
--       init_stack() - initialize the stack pointer
--       push() - push a void* pointer onto the stack
--       pop() - get a void* pointer from the stack
--       empty_stack() - test to see if stack is empty
--
=============================================================================
--                             UPDATE HISTORY                              --
--                                                                         --
-- VER      Date         Explanation of Changes              Author        --
-----------------------------------------------------------------------------
--  0   |  9/93    | Initial version             | C.J. Neerdaels - RAND   --
---------------------------------------------------------------------------*/
/*
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
#include <stdlib.h>
#include "stack.h"
#include "ansihelp.h"

void *xcalloc _PARAMS((int, size_t));	/* Wrapper for calloc(3) */


/*-------------------------------------------------------------------------
--
--  init_stack()
--
--  Function: Move the top of the stack to the base (i.e. forget the data)
--            
--  Inputs:   A pointer to a stack.
--
--  Output:   None.
--
--------------------------------------------------------------------------*/
void init_stack(stack, size)
     Stack *stack;
     int size;
{
    stack->stack_size = size;
    stack->base = (generic_ptr *) xcalloc(size, sizeof(generic_ptr *));
    stack->top = &stack->base[0];
}

/*-------------------------------------------------------------------------
--
--  push()
--
--  Function: Add the element to the static stack array, and increment the
--            top array pointer.
--            
--  Inputs:   A pointer to a stack, a pointer to the data element,
--
--  Output:   None.
--
--------------------------------------------------------------------------*/
void push(stack, data)
     Stack *stack;
     generic_ptr data;
{
    if (current_stacksize(stack) == stack->stack_size) {
	free(data);
	return;
    }
    *stack->top = data;
    stack->top++;
}

/*-------------------------------------------------------------------------
--
--  empty_stack()
--
--  Function: Check if stack is empty.
--            
--  Inputs:   A pointer to a stack.
--
--  Output:   returns 1 if stack is empty.
--
--------------------------------------------------------------------------*/
int empty_stack(stack)
     Stack *stack;
{
    int empty = ((stack->top == &stack->base[0]) ? 1 : 0);
    return (empty);
}
/*-------------------------------------------------------------------------
--
--  full_stack()
--
--  Function: Check if stack is full.
--            
--  Inputs:   A pointer to a stack.
--
--  Output:   returns 1 if stack is full.
--
--------------------------------------------------------------------------*/
int full_stack(stack)
     Stack *stack;
{
    int full = (current_stacksize(stack) == stack->stack_size);
    return (full);
}

/*-------------------------------------------------------------------------
--
--  pop()
--
--  Function: Copy pointer of the top of stack into p_data.  Decrement stack.
--            
--  Inputs:   A pointer to a stack.
--
--  Output:   None.
--
--------------------------------------------------------------------------*/
char *
     pop(stack)
     Stack *stack;
{
    if (empty_stack(stack) == 1) {
	fprintf(stderr, "Stack empty, cannot pop()\n");
	exit(-1);
    }
    stack->top--;
    return (*stack->top);
}
