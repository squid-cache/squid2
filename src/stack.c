/* $Id$ */

#include "squid.h"


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
	safe_free(data);
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
char *pop(stack)
     Stack *stack;
{
    if (empty_stack(stack) == 1)
	fatal("Stack empty, cannot pop()");
    stack->top--;
    return (*stack->top);
}
