/*
 * store_ufs.h
 *
 * Internal declarations for the ufs routines
 */

#ifndef __STORE_NULL_H__
#define __STORE_NULL_H__

/*
 * Store IO stuff
 */
extern STOBJCREATE storeNullCreate;
extern STOBJOPEN storeNullOpen;
extern STOBJCLOSE storeNullClose;
extern STOBJREAD storeNullRead;
extern STOBJWRITE storeNullWrite;
extern STOBJUNLINK storeNullUnlink;

#endif
