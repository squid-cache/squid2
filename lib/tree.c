/* tree - balanced binary tree library
 *
 * vix 05apr94 [removed vixie.h dependencies; cleaned up formatting, names]
 * vix 22jan93 [revisited; uses RCS, ANSI, POSIX; has bug fixes]
 * vix 23jun86 [added delete uar to add for replaced nodes]
 * vix 20jun86 [added tree_delete per wirth a+ds (mod2 v.) p. 224]
 * vix 06feb86 [added tree_mung()]
 * vix 02feb86 [added tree balancing from wirth "a+ds=p" p. 220-221]
 * vix 14dec85 [written]
 */


/* This program text was created by Paul Vixie using examples from the book:
 * "Algorithms & Data Structures," Niklaus Wirth, Prentice-Hall, 1986, ISBN
 * 0-13-022005-1.  Any errors in the conversion from Modula-2 to C are Paul
 * Vixie's.
 *
 * This code and associated documentation is hereby placed in the public
 * domain, with the wish that my name and Prof. Wirth's not be removed
 * from the source or documentation.
 */

#include "config.h"
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "ansiproto.h"
#include "tree.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE !FALSE
#endif

static tree *sprout _PARAMS((tree **, void *, int *, int (*)(), void (*)()));
static int delete _PARAMS((tree **, int (*)(), void *, void (*)(), int *, int *));
static void del _PARAMS((tree **, int *, tree **, void (*)(), int *));
static void bal_L _PARAMS((tree **, int *));
static void bal_R _PARAMS((tree **, int *));

void
tree_init(ppr_tree)
     tree **ppr_tree;
{
    *ppr_tree = NULL;
    return;
}

void *
tree_srch(ppr_tree, pfi_compare, p_user)
     tree **ppr_tree;
     int (*pfi_compare) ();
     void *p_user;
{
    register int i_comp;
    if (*ppr_tree) {
	i_comp = (*pfi_compare) (p_user, (**ppr_tree).data);
	if (i_comp > 0)
	    return tree_srch(&(**ppr_tree).right,
		pfi_compare,
		p_user);
	if (i_comp < 0)
	    return tree_srch(&(**ppr_tree).left,
		pfi_compare,
		p_user);
	/* not higher, not lower... this must be the one.
	 */
	return (**ppr_tree).data;
    }
    /* grounded. NOT found.
     */
    return NULL;
}

void *
tree_add(ppr_tree, pfi_compare, p_user, pfv_uar)
     tree **ppr_tree;
     int (*pfi_compare) ();
     void *p_user;
     void (*pfv_uar) ();
{
    int i_balance = FALSE;
    if (!sprout(ppr_tree, p_user, &i_balance, pfi_compare, pfv_uar))
	return NULL;
    return p_user;
}

int
tree_delete(ppr_p, pfi_compare, p_user, pfv_uar)
     tree **ppr_p;
     int (*pfi_compare) ();
     void *p_user;
     void (*pfv_uar) ();
{
    int i_balance = FALSE, i_uar_called = FALSE;
    return delete(ppr_p, pfi_compare, p_user, pfv_uar,
	&i_balance, &i_uar_called);
}

int
tree_trav(ppr_tree, pfi_uar)
     tree **ppr_tree;
     int (*pfi_uar) ();
{
    if (!*ppr_tree)
	return TRUE;
    if (!tree_trav(&(**ppr_tree).left, pfi_uar))
	return FALSE;
    if (!(*pfi_uar) ((**ppr_tree).data))
	return FALSE;
    if (!tree_trav(&(**ppr_tree).right, pfi_uar))
	return FALSE;
    return TRUE;
}

void
tree_mung(ppr_tree, pfv_uar)
     tree **ppr_tree;
     void (*pfv_uar) ();
{
    if (*ppr_tree) {
	tree_mung(&(**ppr_tree).left, pfv_uar);
	tree_mung(&(**ppr_tree).right, pfv_uar);
	if (pfv_uar)
	    (*pfv_uar) ((**ppr_tree).data);
	free(*ppr_tree);
	*ppr_tree = NULL;
    }
    return;
}

static tree *
sprout(ppr, p_data, pi_balance, pfi_compare, pfv_delete)
     tree **ppr;
     void *p_data;
     int *pi_balance;
     int (*pfi_compare) ();
     void (*pfv_delete) ();
{
    tree *p1, *p2, *sub;
    int cmp;
    /* are we grounded?  if so, add the node "here" and set the rebalance
     * flag, then exit.
     */
    if (!*ppr) {
	*ppr = (tree *) malloc(sizeof(tree));
	if (*ppr) {
	    (*ppr)->left = NULL;
	    (*ppr)->right = NULL;
	    (*ppr)->bal = 0;
	    (*ppr)->data = p_data;
	    *pi_balance = TRUE;
	}
	return *ppr;
    }
    /* compare the data using routine passed by caller.
     */
    cmp = (*pfi_compare) (p_data, (*ppr)->data);
    /* if LESS, prepare to move to the left.
     */
    if (cmp < 0) {
	sub = sprout(&(*ppr)->left, p_data, pi_balance,
	    pfi_compare, pfv_delete);
	if (sub && *pi_balance) {	/* left branch has grown */
	    switch ((*ppr)->bal) {
	    case 1:		/* right branch WAS longer; bal is ok now */
		(*ppr)->bal = 0;
		*pi_balance = FALSE;
		break;
	    case 0:		/* balance WAS okay; now left branch longer */
		(*ppr)->bal = -1;
		break;
	    case -1:		/* left branch was already too long. rebal */
		p1 = (*ppr)->left;
		if (p1->bal == -1) {	/* LL */
		    (*ppr)->left = p1->right;
		    p1->right = *ppr;
		    (*ppr)->bal = 0;
		    *ppr = p1;
		} else {	/* double LR */
		    p2 = p1->right;
		    p1->right = p2->left;
		    p2->left = p1;
		    (*ppr)->left = p2->right;
		    p2->right = *ppr;
		    if (p2->bal == -1)
			(*ppr)->bal = 1;
		    else
			(*ppr)->bal = 0;
		    if (p2->bal == 1)
			p1->bal = -1;
		    else
			p1->bal = 0;
		    *ppr = p2;
		}		/*else */
		(*ppr)->bal = 0;
		*pi_balance = FALSE;
	    }			/*switch */
	}			/*if */
	return sub;
    }				/*if */
    /* if MORE, prepare to move to the right.
     */
    if (cmp > 0) {
	sub = sprout(&(*ppr)->right, p_data, pi_balance,
	    pfi_compare, pfv_delete);
	if (sub && *pi_balance) {
	    switch ((*ppr)->bal) {
	    case -1:
		(*ppr)->bal = 0;
		*pi_balance = FALSE;
		break;
	    case 0:
		(*ppr)->bal = 1;
		break;
	    case 1:
		p1 = (*ppr)->right;
		if (p1->bal == 1) {	/* RR */
		    (*ppr)->right = p1->left;
		    p1->left = *ppr;
		    (*ppr)->bal = 0;
		    *ppr = p1;
		} else {	/* double RL */
		    p2 = p1->left;
		    p1->left = p2->right;
		    p2->right = p1;
		    (*ppr)->right = p2->left;
		    p2->left = *ppr;
		    if (p2->bal == 1)
			(*ppr)->bal = -1;
		    else
			(*ppr)->bal = 0;
		    if (p2->bal == -1)
			p1->bal = 1;
		    else
			p1->bal = 0;
		    *ppr = p2;
		}		/*else */
		(*ppr)->bal = 0;
		*pi_balance = FALSE;
	    }			/*switch */
	}			/*if */
	return sub;
    }				/*if */
    /* not less, not more: this is the same key!  replace...
     */
    *pi_balance = FALSE;
    if (pfv_delete)
	(*pfv_delete) ((*ppr)->data);
    (*ppr)->data = p_data;
    return *ppr;
}

static int
delete(ppr_p, pfi_compare, p_user, pfv_uar, pi_balance, pi_uar_called)
     tree **ppr_p;
     int (*pfi_compare) ();
     void *p_user;
     void (*pfv_uar) ();
     int *pi_balance;
     int *pi_uar_called;
{
    tree *pr_q;
    int i_comp, i_ret;
    if (*ppr_p == NULL) {
	return FALSE;
    }
    i_comp = (*pfi_compare) ((*ppr_p)->data, p_user);
    if (i_comp > 0) {
	i_ret = delete(&(*ppr_p)->left, pfi_compare, p_user, pfv_uar,
	    pi_balance, pi_uar_called);
	if (*pi_balance)
	    bal_L(ppr_p, pi_balance);
    } else if (i_comp < 0) {
	i_ret = delete(&(*ppr_p)->right, pfi_compare, p_user, pfv_uar,
	    pi_balance, pi_uar_called);
	if (*pi_balance)
	    bal_R(ppr_p, pi_balance);
    } else {
	pr_q = *ppr_p;
	if (pr_q->right == NULL) {
	    *ppr_p = pr_q->left;
	    *pi_balance = TRUE;
	} else if (pr_q->left == NULL) {
	    *ppr_p = pr_q->right;
	    *pi_balance = TRUE;
	} else {
	    del(&pr_q->left, pi_balance, &pr_q,
		pfv_uar, pi_uar_called);
	    if (*pi_balance)
		bal_L(ppr_p, pi_balance);
	}
	if (!*pi_uar_called && pfv_uar)
	    (*pfv_uar) (pr_q->data);
	free(pr_q);		/* thanks to wuth@castrov.cuc.ab.ca */
	i_ret = TRUE;
    }
    return i_ret;
}

static void
del(ppr_r, pi_balance, ppr_q, pfv_uar, pi_uar_called)
     tree **ppr_r;
     int *pi_balance;
     tree **ppr_q;
     void (*pfv_uar) ();
     int *pi_uar_called;
{
    if ((*ppr_r)->right != NULL) {
	del(&(*ppr_r)->right, pi_balance, ppr_q,
	    pfv_uar, pi_uar_called);
	if (*pi_balance)
	    bal_R(ppr_r, pi_balance);
    } else {
	if (pfv_uar)
	    (*pfv_uar) ((*ppr_q)->data);
	*pi_uar_called = TRUE;
	(*ppr_q)->data = (*ppr_r)->data;
	*ppr_q = *ppr_r;
	*ppr_r = (*ppr_r)->left;
	*pi_balance = TRUE;
    }
    return;
}

static void
bal_L(ppr_p, pi_balance)
     tree **ppr_p;
     int *pi_balance;
{
    tree *p1, *p2;
    int b1, b2;
    switch ((*ppr_p)->bal) {
    case -1:
	(*ppr_p)->bal = 0;
	break;
    case 0:
	(*ppr_p)->bal = 1;
	*pi_balance = FALSE;
	break;
    case 1:
	p1 = (*ppr_p)->right;
	b1 = p1->bal;
	if (b1 >= 0) {
	    (*ppr_p)->right = p1->left;
	    p1->left = *ppr_p;
	    if (b1 == 0) {
		(*ppr_p)->bal = 1;
		p1->bal = -1;
		*pi_balance = FALSE;
	    } else {
		(*ppr_p)->bal = 0;
		p1->bal = 0;
	    }
	    *ppr_p = p1;
	} else {
	    p2 = p1->left;
	    b2 = p2->bal;
	    p1->left = p2->right;
	    p2->right = p1;
	    (*ppr_p)->right = p2->left;
	    p2->left = *ppr_p;
	    if (b2 == 1)
		(*ppr_p)->bal = -1;
	    else
		(*ppr_p)->bal = 0;
	    if (b2 == -1)
		p1->bal = 1;
	    else
		p1->bal = 0;
	    *ppr_p = p2;
	    p2->bal = 0;
	}
    }
    return;
}

static void
bal_R(ppr_p, pi_balance)
     tree **ppr_p;
     int *pi_balance;
{
    tree *p1, *p2;
    int b1, b2;
    switch ((*ppr_p)->bal) {
    case 1:
	(*ppr_p)->bal = 0;
	break;
    case 0:
	(*ppr_p)->bal = -1;
	*pi_balance = FALSE;
	break;
    case -1:
	p1 = (*ppr_p)->left;
	b1 = p1->bal;
	if (b1 <= 0) {
	    (*ppr_p)->left = p1->right;
	    p1->right = *ppr_p;
	    if (b1 == 0) {
		(*ppr_p)->bal = -1;
		p1->bal = 1;
		*pi_balance = FALSE;
	    } else {
		(*ppr_p)->bal = 0;
		p1->bal = 0;
	    }
	    *ppr_p = p1;
	} else {
	    p2 = p1->right;
	    b2 = p2->bal;
	    p1->right = p2->left;
	    p2->left = p1;
	    (*ppr_p)->left = p2->right;
	    p2->right = *ppr_p;
	    if (b2 == -1)
		(*ppr_p)->bal = 1;
	    else
		(*ppr_p)->bal = 0;
	    if (b2 == 1)
		p1->bal = -1;
	    else
		p1->bal = 0;
	    *ppr_p = p2;
	    p2->bal = 0;
	}
    }
    return;
}
