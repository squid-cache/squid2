#include "squid.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <ctype.h>
#ifdef linux
#include <string.h>
#include <stdlib.h>
#endif


#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_config.h"

viewEntry	*views = NULL;
usecEntry	*users = NULL;
communityEntry  *communities = NULL;
int		 maintenanceView = 0;

static int linenumber = 0;

/* XXX: create function: */
#define xstrdup		strdup

/* fwd: */
/* from usec.c: */
extern void v2md5auth_password_to_key();


char *gettoken( tokenptr )
char **tokenptr;
{
	char *p = *tokenptr;
	char *tp;
	char  ch;

	while( (ch = *p) && isspace(ch) ) p++;
	tp = p;
	while( (ch = *p) && !isspace(ch) ) p++;
	if( *p ) *p++ = '\0';
	*tokenptr = p;
	return tp;
}


static void
tokenize( line, tokens, max_tokens )
char *line;
char *tokens[];
int   max_tokens;
{
	int   i;
	char *tokenptr;

	tokenptr = line;
	for( i = 0; i < max_tokens; i++ ) {
		tokens[i] = gettoken( &tokenptr );
		if( tokens[i][0] == '\0' ) break;
	}
	for( ; i < max_tokens; i++ ) tokens[i] = "";
}

int create_view( tokens )
char *tokens[];
{
	static int 	 nextview = 1;
	viewEntry	*vp;
	viewEntry	*new, *prev = 0;

	if( tokens[3][0] == 0 || tokens[4][0] != 0 ) {
		debug(49,0)( "create_view: bad view line, line %d\n", linenumber );
		return -1;
	}

	if( strlen(tokens[1]) > (sizeof(vp->viewName) - 1) ) {
		debug(49,0)( "create_view:view name too long, line %d\n", linenumber );
		return -1;
	}

	for( vp = views; vp; prev = vp, vp = vp->next ) {
		if( strcmp( tokens[1], vp->viewName ) == 0 ) break;
	}

	new = (viewEntry *)calloc(1,  sizeof(viewEntry) );
	memset( new, 0, sizeof(viewEntry) );

	strcpy( new->viewName, tokens[1] );
	new->viewIndex = vp ? vp->viewIndex : nextview++;
	new->viewType = strcmp(tokens[3],"included") ? VIEWEXCLUDED : VIEWINCLUDED;

	new->viewSubtreeLen = sizeof(vp->viewSubtree)/sizeof(oid);
	if (!read_objid(tokens[2], new->viewSubtree, &new->viewSubtreeLen)) {
	}

	if( views ) {
		for( ; vp; prev = vp, vp = vp->next ) ;
		prev->next = new;
	} else {
		views = new;
	}

	return new->viewIndex;
}

static int
find_view( name )
char *name;
{
	viewEntry *vp;

	if( strcmp( name, "-" ) == 0 ) return 0;

	for( vp = views; vp; vp = vp->next ) {
		if( strcmp( vp->viewName, name ) == 0 ) return vp->viewIndex;
	}
	return -1;
}

int create_user( tokens )
char *tokens[];
{
	usecEntry	*up;
	usecEntry	*new, *prev = 0;
	char		*start, *cp;
	int		 ch;
	int		 i;

	if( tokens[5][0] == 0 || tokens[6][0] != 0 ) {
		debug(49,0)( "create_user: bad user line, line %d\n", linenumber );
		return -1;
	}

	if( strlen(tokens[1]) > (sizeof(up->userName) - 1) ) {
		debug(49,0) ( "create_user: user name too long, line %d\n", linenumber );
		return -1;
	}

	for( up = users; up; prev = up, up = up->next ) {
		if( strcmp( tokens[1], up->userName ) == 0 ) break;
	}

	if( up ) {
		debug(49,0)( "create_user: user '%s' already defined\n", tokens[1] );
		return -1;
	}

	new = (usecEntry *)calloc(1,  sizeof(usecEntry) );
	if( users ) {
		prev->next = new;
	} else {
		users = new;
	}

	memset( new, 0, sizeof(usecEntry) );
	new->noauthReadView = find_view( tokens[1] );
	new->noauthWriteView = find_view( tokens[2] );
	new->authReadView = find_view( tokens[3] );
	new->authWriteView = find_view( tokens[4] );
	if( new->noauthReadView < 0 || new->noauthWriteView < 0 
	 || new->authReadView < 0 || new->authWriteView < 0 ) {
		debug(49,0)("create_user: unknown view name referenced, line %d\n", linenumber );
		return -1;
	}

	start = cp = tokens[5];
	while( *cp && *cp != '/' ) cp++;
	new->userLen = cp - start;
	strncpy( new->userName, start, cp - start );

	if( new->userLen == 0 ) {
		debug(49,0)( "create_user: user name invalid, line %d\n", linenumber );
		return -1;
	}

	/* look for authKey */
	if( *cp != '/' ) return 0;
	cp++;

	start = cp;
	while( *cp && *cp != '/' ) cp++;
	if( (cp - start > 2) && (strncmp( start, "0x", 2 ) == 0) ) {
		if( cp - start != 34 ) {
			debug(49,0)("create_user: auth key not 16 octets\n" );
			return -1;
		}

		start += 2;
		for( i = 0; i < 16; i++ ) {
			if( sscanf( start, "%2x", &ch ) != 1 ) {
				debug(49,0)( "create_user: auth key contains non hex digits\n" );
				return -1;
			}
			start += 2;
			new->authKey[i] = ch;
		}
		new->qoS |= USEC_QOS_AUTH;
	} else if( cp - start > 0 ) {
		v2md5auth_password_to_key( start, cp - start, new->authKey );
		new->qoS |= USEC_QOS_AUTH;
	}

	/* look for privKey */
	if( *cp != '/' ) return 0;
	cp++;

	start = cp;
	while( *cp && *cp != '/' ) cp++;
	if( (cp - start > 2) && (strncmp( start, "0x", 2 ) == 0) ) {
		if( cp - start != 34 ) {
			debug(49,0)( "create_user: priv key not 16 octets\n" );
			return -1;
		}

		start += 2;
		for( i = 0; i < 16; i++ ) {
			if( sscanf( start, "%2x", &ch ) != 1 ) {
				debug(49,0)( "create_user: priv key contains non hex digits\n" );
				return -1;
			}
			new->privKey[i] = ch;
			start += 2;
		}
		new->qoS |= USEC_QOS_PRIV;
	} else if( cp - start > 0 ) {
		v2md5auth_password_to_key( start, cp - start, new->privKey );
		new->qoS |= USEC_QOS_PRIV;
	}

	return 0;
}

static int
create_community( tokens )
char *tokens[];
{
	communityEntry	*cp;
	communityEntry	*new, *prev = 0;

	if( tokens[3][0] == 0 || tokens[4][0] != 0 ) {
		debug(49,0)("create_community: bad community line, line %d\n", linenumber );
		return -1;
	}

	if( strlen(tokens[1]) > (sizeof(cp->name) - 1) ) {
		debug(49,0)( "create_community: community name too long, line %d\n", 
			 linenumber );
		return -1;
	}

	for( cp = communities; cp; prev = cp, cp = cp->next ) {
		if( strcmp( tokens[1], cp->name ) == 0 ) break;
	}

	if( cp ) {
		debug(49,0)( "create_community: community '%s' already defined\n", 
			 tokens[1] );
		return -1;
	}

	new = (communityEntry *)calloc(1,  sizeof(communityEntry) );
	memset( new, 0, sizeof(communityEntry) );
	strcpy( new->name, tokens[1] );
	new->readView = find_view( tokens[2] );
	new->writeView = find_view( tokens[3] );
	if( new->readView < 0 || new->writeView < 0 ) {
		debug(49,0)( "create_community: unknown view name referenced, line %d\n",
			 linenumber );
		return -1;
	}

	if( communities ) {
		prev->next = new;
	} else {
		communities = new;
	}

	return 0;
}

int 
read_config()
{
	FILE    *f;
	char	 buff[200];
	char	*tokens[10];
	/* comes from snmpd.c: */
	extern char *snmp_configfile;

	init_mib();

	if (snmp_configfile==NULL)
		fatal("snmp.c : read_config() with a NULL snmp_configfile!\n");

	debug(49,1)("snmp read_config() , opening %s\n",snmp_configfile);

	if( (f = fopen( snmp_configfile, "r" )) == NULL ) 
		fatal("Cannot open configuration file, exiting.\n");

	while( fgets( buff, sizeof(buff), f ) ) {
		linenumber++;
		if( buff[0] == '#' ) continue;

		tokenize( buff, tokens, 10 );
		if( tokens[0][0] == 0 ) continue;

		if( strcmp( "view", tokens[0] ) == 0 ) {
			if( create_view( tokens ) < 0 ) return -1;
		} else if( strcmp( "user", tokens[0] ) == 0 ) {
			if( create_user( tokens ) < 0 ) return -1;
		} else if( strcmp( "community", tokens[0] ) == 0 ) {
			if( create_community( tokens ) < 0 ) return -1;
		}
	}

	tokenize( xstrdup ("view $$INTERNAL$$ .1.3.6.1.6.3.6.1 included"), 
		  tokens, 10 );
	maintenanceView = create_view( tokens );
	tokenize( xstrdup ("view $$INTERNAL$$ .1.3.6.1.6.3.1.1.1 included")
		  , tokens, 10 );
	create_view( tokens );

	fclose( f );

	return 0;
}

