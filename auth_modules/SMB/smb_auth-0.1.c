/*
 *  smb_auth.c
 * 
 *  Copyright 1998 Richard Huveneers
 *  Distributed under the GPL
 * 
 *  31 July 1998, version 0.01:
 *    initial release
 */

#include <stdio.h>
#include <string.h>

#include "valid.h"

#define BUFSIZE		256
#define NUMNTDOMAINS	2

struct NTDOMAIN {
    char *name;			/* NT domain name */
    char *abbrev;		/* short name for the lazy people, "" means none specified */
    char *dc;			/* authenticate against this domain controller */
    char *dc2;			/* use this domain controller if dc does not respond */

};



struct NTDOMAIN ntd[NUMNTDOMAINS] =
{
    {"NETATWORK", "NW", "SERVER1", "SERVER1"},
    {"MEDIA@VANTAGE", "", "VEGA", "VEGA"}
};


void
main(int argc, char *argv[])
{
    int i, isvalid;
    char buf[BUFSIZE];
    char *p;
    char *ntdname;
    /* make standard output line buffered */
    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
	return;
    while (1) {
	if (fgets(buf, BUFSIZE, stdin) == NULL)
	    break;
	if ((p = strchr(buf, '\n')) == NULL)
	    continue;
	*p = '\0';
	if ((p = strchr(buf, ' ')) == NULL) {
	    (void) printf("ERR\n");
	    continue;
	}
	*p++ = '\0';
	if ((ntdname = strchr(buf, '\\')) == NULL)
	    ntdname = "";
	else
	    *ntdname++ = '\0';
	isvalid = 0;
	for (i = 0; i < NUMNTDOMAINS; i++) {
	    if (strcasecmp(ntdname, ntd[i].name) == 0 || strcasecmp(ntdname, ntd[i].abbrev) == 0) {
		if (Valid_User(buf, p, ntd[i].dc, ntd[i].dc2, ntd[i].name) == NTV_NO_ERROR) {
		    isvalid = 1;
		    break;
		}
	    }
	}
	(void) printf(isvalid ? "OK\n" : "ERR\n");
    }
}
