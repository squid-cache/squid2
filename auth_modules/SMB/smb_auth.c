/*
 *  smb_auth - SMB proxy authentication module
 *  Copyright (C) 1998  Richard Huveneers <richard@hekkihek.hacom.nl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE			256
#define NMB_UNICAST		1
#define NMB_BROADCAST	2

struct SMBDOMAIN
{
	char				*name;		/* domain name */
	char				*sname;		/* match this with user input */
	char				*nmbaddr;	/* name service address */
	int					nmbcast;	/* broadcast or unicast */
	struct SMBDOMAIN	*next;		/* linked list */
};

struct SMBDOMAIN *firstdom = NULL;
struct SMBDOMAIN *lastdom = NULL;

void main(int argc, char *argv[])
{
	int					i;
	char				buf[BUFSIZE];
	struct SMBDOMAIN	*dom;
	char				*s;
	char				*user;
	char				*pass;
	char				*domname;
	FILE				*p;

	/* make standard output line buffered */
	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		return;

	/* parse command line arguments */
	for (i = 1; i < argc; i++)
	{
		/* the next options require an argument */
		if (i + 1 == argc)
			break;

		if (strcmp(argv[i], "-W") == 0)
		{
			if ((dom = (struct SMBDOMAIN *) malloc(sizeof(struct SMBDOMAIN))) == NULL)
				return;

			dom->name = dom->sname = argv[++i];
			dom->nmbaddr = "";
			dom->nmbcast = NMB_BROADCAST;
			dom->next = NULL;

			/* append to linked list */
			if (lastdom != NULL)
				lastdom->next = dom;
			else
				firstdom = dom;

			lastdom = dom;
			continue;
		}

		if (strcmp(argv[i], "-w") == 0)
		{
			if (lastdom != NULL)
				lastdom->sname = argv[++i];
			continue;
		}

		if (strcmp(argv[i], "-B") == 0)
		{
			if (lastdom != NULL)
			{
				lastdom->nmbaddr = argv[++i];
				lastdom->nmbcast = NMB_BROADCAST;
			}
			continue;
		}

		if (strcmp(argv[i], "-U") == 0)
		{
			if (lastdom != NULL)
			{
				lastdom->nmbaddr = argv[++i];
				lastdom->nmbcast = NMB_UNICAST;
			}
			continue;
		}
	}

	while (1)
	{
		if (fgets(buf, BUFSIZE, stdin) == NULL)
			break;

		if ((s = strchr(buf, '\n')) == NULL)
			continue;
		*s = '\0';

		if ((s = strchr(buf, ' ')) == NULL)
		{
			(void) printf("ERR\n");
			continue;
		}
		*s = '\0';

		user = buf;
		pass = s + 1;
		domname = NULL;

		if ((s = strchr(user, '\\')) != NULL)
		{
			*s = '\0';
			domname = user;
			user = s + 1;
		}

		/* match domname with linked list */
		if (domname != NULL && strlen(domname) > 0)
		{
			for (dom = firstdom; dom != NULL; dom = dom->next)
				if (strcasecmp(dom->sname, domname) == 0)
					break;
		} else
			dom = firstdom;

		if (dom == NULL)
		{
			(void) printf("ERR\n");
			continue;
		}

		if ((p = popen(HELPERSCRIPT " > /dev/null 2>&1", "w")) == NULL)
		{
			(void) printf("ERR\n");
			continue;
		}

		(void) fprintf(p, "%s\n", SAMBAPREFIX);
		(void) fprintf(p, "%s\n", dom->name);
		(void) fprintf(p, "%s\n", dom->nmbaddr);
		(void) fprintf(p, "%d\n", dom->nmbcast);
		(void) fprintf(p, "%s\n", user);
		(void) fprintf(p, "%s\n", pass);
		(void) fflush(p);

		if (pclose(p) == 0)
			(void) printf("OK\n");
		else
			(void) printf("ERR\n");

	} /* while (1) */
}
