/* tree.h - declare structures used by tree library
 *
 * vix 22jan93 [revisited; uses RCS, ANSI, POSIX; has bug fixes]
 * vix 27jun86 [broken out of tree.c]
 *
 * $Id$
 */


#ifndef	_TREE_H_INCLUDED
#define	_TREE_H_INCLUDED

typedef struct tree_s {
    void *data;
    short bal;
    struct tree_s *left, *right;
} tree;

void tree_init(tree **);
void *tree_srch(tree **, int (*)(), void *);
void *tree_add(tree **, int (*)(), void *, void (*)());
int tree_delete(tree **, int (*)(), void *, void (*)());
int tree_trav(tree **, int (*)());
void tree_mung(tree **, void (*)());

#endif /* _TREE_H_INCLUDED */
