/* $Id$ */

#ifndef _STACK_H_
#define _STACK_H_

#define current_stacksize(stack) ((stack)->top - (stack)->base)

typedef char *generic_ptr;

typedef struct {
    generic_ptr *base;
    generic_ptr *top;
    int stack_size;
} Stack;

extern char *pop _PARAMS((Stack *));
extern int empty_stack _PARAMS((Stack *));
extern int full_stack _PARAMS((Stack *));
extern void push _PARAMS((Stack *, generic_ptr));
extern void init_stack _PARAMS((Stack *, int));

#endif /* _STACK_H_ */
