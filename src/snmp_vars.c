#include "squid.h"

#include "mib_module.h"
#include "snmp_config.h"

#define PROCESSSLOTINDEX  0
#define PROCESSID         4
#define PROCESSCOMMAND    8
 
#ifdef vax11c
#define ioctl socket_ioctl
#define perror socket_perror
#endif vax11c

extern  int swap, mem;

/* fwd: */
static int compare_tree ();

int snmp_enableauthentraps;
#define TALLOC(T)	((T *) xmalloc (sizeof(T)))


/*
 *	Each variable name is placed in the variable table, without the
 * terminating substring that determines the instance of the variable.  When
 * a string is found that is lexicographicly preceded by the input string,
 * the function for that entry is called to find the method of access of the
 * instance of the named variable.  If that variable is not found, NULL is
 * returned, and the search through the table continues (it will probably
 * stop at the next entry).  If it is found, the function returns a character
 * pointer and a length or a function pointer.  The former is the address
 * of the operand, the latter is a write routine for the variable.
 *
 * u_char *
 * findVar(name, length, exact, var_len, write_method)
 * oid	    *name;	    IN/OUT - input name requested, output name found
 * int	    length;	    IN/OUT - number of sub-ids in the in and out oid's
 * int	    exact;	    IN - TRUE if an exact match was requested.
 * int	    len;	    OUT - length of variable or 0 if function returned.
 * int	    write_method;   OUT - pointer to function to set variable,
 *                                otherwise 0
 *
 *     The writeVar function is returned to handle row addition or complex
 * writes that require boundary checking or executing an action.
 * This routine will be called three times for each varbind in the packet.
 * The first time for each varbind, action is set to RESERVE1.  The type
 * and value should be checked during this pass.  If any other variables
 * in the MIB depend on this variable, this variable will be stored away
 * (but *not* committed!) in a place where it can be found by a call to
 * writeVar for a dependent variable, even in the same PDU.  During
 * the second pass, action is set to RESERVE2.  If this variable is dependent
 * on any other variables, it will check them now.  It must check to see
 * if any non-committed values have been stored for variables in the same
 * PDU that it depends on.  Sometimes resources will need to be reserved
 * in the first two passes to guarantee that the operation can proceed
 * during the third pass.  During the third pass, if there were no errors
 * in the first two passes, writeVar is called for every varbind with action
 * set to COMMIT.  It is now that the values should be written.  If there
 * were errors during the first two passes, writeVar is called in the third
 * pass once for each varbind, with the action set to FREE.  An opportunity
 * is thus provided to free those resources reserved in the first two passes.
 * 
 * writeVar(action, var_val, var_val_type, var_val_len, statP, name, name_len)
 * int	    action;	    IN - RESERVE1, RESERVE2, COMMIT, or FREE
 * u_char   *var_val;	    IN - input or output buffer space
 * u_char   var_val_type;   IN - type of input buffer
 * int	    var_val_len;    IN - input and output buffer len
 * u_char   *statP;	    IN - pointer to local statistic
 * oid      *name           IN - pointer to name requested
 * int      name_len        IN - number of sub-ids in the name
 */
#ifndef CLSIZE
#define CLSIZE 256
#endif
#ifndef NBPG
#define NBPG 1
#endif

long		long_return;
#if !defined(ibm032) && !defined(linux)
u_char		return_buf[CLSIZE*NBPG];  
#else
u_char		return_buf[256]; /* nee 64 */
#define CLSIZE	256	/* XXX: ??? */
#endif

#define CMUMIB 		1, 3, 6, 1, 4, 1, 3
#define CMUUNIXMIB  	CMUMIB, 2, 2

#define SNMPMODULES 		1, 3, 6, 1, 6, 3

#define SNMPSTATS		SNMPMODULES, 1, 1, 1
#define SNMPV1STATS		SNMPMODULES, 1, 1, 2
#define SNMPTRAP		SNMPMODULES, 1, 1, 4
#define SNMPSET			SNMPMODULES, 1, 1, 6
#define USECMIBOBJ		SNMPMODULES, 6, 1
#define USECAGENT		USECMIBOBJ, 1
#define USECSTATS		USECMIBOBJ, 2


#ifndef linux

#define HOST                    RMONMIB, 4
#define HOSTCONTROL             HOST, 1, 1                      /* hostControlEntry */
#define HOSTTAB                 HOST, 2, 1                      /* hostEntry */
#define HOSTTIMETAB             HOST, 3, 1                      /* hostTimeEntry */
#define HOSTTOPN                RMONMIB, 5
#define HOSTTOPNCONTROL HOSTTOPN, 1, 1          /* hostTopNControlEntry */
#define HOSTTOPNTAB             HOSTTOPN, 2, 1          /* hostTopNEntry */
#define HOSTTIMETABADDRESS                                      1
#define HOSTTIMETABCREATIONORDER                        2
#define HOSTTIMETABINDEX                                        3
#define HOSTTIMETABINPKTS                                       4
#define HOSTTIMETABOUTPKTS                                      5
#define HOSTTIMETABINOCTETS                                     6
#define HOSTTIMETABOUTOCTETS                            7
#define HOSTTIMETABOUTERRORS                            8
#define HOSTTIMETABOUTBCASTPKTS                         9
#define HOSTTIMETABOUTMCASTPKTS                         10

/* various OIDs that are needed throughout the agent */

oid sysUpTimeOid[] = {1,3,6,1,2,1,1,3,0};
int sysUpTimeOidLen = sizeof(sysUpTimeOid)/sizeof(oid);

#endif /* ! linux */

/*
 * The subtree structure contains a subtree prefix which applies to
 * all variables in the associated variable list.
 * No subtree may be a subtree of another subtree in this list.  i.e.:
 * 1.2
 * 1.2.0
 */
struct subtree {
    oid			name[16];	/* objid prefix of subtree */
    u_char 		namelen;	/* number of subid's in name above */
    struct variable	*variables;   /* pointer to variables array */
    int			variables_len;	/* number of entries in above array */
    int			variables_width; /* sizeof each variable entry */
    struct subtree *next;
};

#if 1
#define variable2 variable
#define variable4 variable
#define variable7 variable
#define variable13 variable
#else

/*
 * This is a new variable structure that doesn't have as much memory
 * tied up in the object identifier.  It's elements have also been re-arranged
 * so that the name field can be variable length.  Any number of these
 * structures can be created with lengths tailor made to a particular
 * application.  The first 5 elements of the structure must remain constant.
 */
struct variable2 {
    u_char          magic;          /* passed to function as a hint */
    char            type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    SNMPFV	    *findVar;       /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[2];        /* object identifier of variable */
};

struct variable4 {
    u_char          magic;          /* passed to function as a hint */
    char            type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    SNMPFV	    *findVar;       /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[4];        /* object identifier of variable */
};

struct variable7 {
    u_char          magic;          /* passed to function as a hint */
    char            type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    SNMPFV	    *findVar;       /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[7];        /* object identifier of variable */
};

struct variable13 {
    u_char          magic;          /* passed to function as a hint */
    char            type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    SNMPFV	    *findVar;	    /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[13];       /* object identifier of variable */
};

#endif

/*
 * ##############################################################
 * IMPORTANT NOTE:
 * ##############################################################
 *
 * The format of the acl word in these entries has changed.  It is still
 * 2 bits per community, offset from the right by the index of the community.
 * The leftmost two bits denotes read access, and the rightmost denotes
 * write access.
 * The change is that the rightmost two bits are now reserved for the object's
 * max-access.  This is the minimum of what makes "protocol sense" for the
 * object and whether set support was implemented for that object.
 * These two bits will not map to any community.  The first community
 * entry will map to the 3rd and 4th bits.
 */

#define MTRBIGNUMBER	1
#define MTRNSAPADDRESS	2
#define MTRBITSTRING	3


/*
 * Note that the name field must be larger than any name that might
 * match that object.  For these variable length (objid) indexes
 * this might seem to be hard, but placing MAXINT in the first
 * subid of the index denotes an obcenely long objid, thereby ensuring that
 * none slip through.
 */
/* No access for community SNMP, RW possible for Secure SNMP */
#define PRIVRW   0x0003  
/* No access for community SNMP, RO possible for Secure SNMP */
#define PRIVRO   0x0002

#ifndef linux
u_char *var_hosttimetab();
#endif

static struct subtree *subtrees = 0;
#ifdef HM_HA
void
snmp_vars_init ()
{
/*
    { static oid base[] = {MIB, 1};
      mib_register (base, 7, system_variables,
	 sizeof(system_variables)/sizeof(*system_variables),
	 sizeof(*system_variables));
    }
    { static oid base[] = {MIB, 1, 9, 1};
      mib_register (base, 9, (struct variable *)or_variables,
	 sizeof(or_variables)/sizeof(*or_variables),
	 sizeof(*or_variables));
    }
    { static oid base[] = {MIB, 2};
      mib_register (base, 7, (struct variable *)interface_variables,
	 sizeof(interface_variables)/sizeof(*interface_variables),
	 sizeof(*interface_variables));
    }
    { static oid base[] = {MIB, 3, 1, 1};
      mib_register (base, 9, (struct variable *)at_variables,
	 sizeof(at_variables)/sizeof(*at_variables),
	 sizeof(*at_variables));
    }
    { static oid base[] = {MIB, 4};
      mib_register (base, 7, (struct variable *)ip_variables,
	 sizeof(ip_variables)/sizeof(*ip_variables),
	 sizeof(*ip_variables));
    }
    { static oid base[] = {MIB, 5};
      mib_register (base, 7, (struct variable *)icmp_variables,
	 sizeof(icmp_variables)/sizeof(*icmp_variables),
	 sizeof(*icmp_variables));
    }
    { static oid base[] = {MIB, 6};
      mib_register (base, 7, (struct variable *)tcp_variables,
	 sizeof(tcp_variables)/sizeof(*tcp_variables),
	 sizeof(*tcp_variables));
    }
    { static oid base[] = {MIB, 7};
      mib_register (base, 7, (struct variable *)udp_variables,
	 sizeof(udp_variables)/sizeof(*udp_variables),
	 sizeof(*udp_variables));
    }

#ifdef linux
    { static oid base[] = {MIB, 11};
      mib_register (base, 7, (struct variable *)snmp_variables,
	 sizeof(snmp_variables)/sizeof(*snmp_variables),
	 sizeof(*snmp_variables));
    }
#endif

    { static oid base[] = {SNMPSTATS};
      mib_register (base, 9, (struct variable *)snmpstats_variables,
	 sizeof(snmpstats_variables)/sizeof(*snmpstats_variables),
	 sizeof(*snmpstats_variables));
    }
    { static oid base[] = {SNMPV1STATS};
      mib_register (base, 9, (struct variable *)snmpv1stats_variables,
	 sizeof(snmpv1stats_variables)/sizeof(*snmpv1stats_variables),
	 sizeof(*snmpv1stats_variables));
    }
    { static oid base[] = {SNMPTRAP};
      mib_register (base, 9, (struct variable *)v2authtraps_variables,
	 sizeof(v2authtraps_variables)/sizeof(*v2authtraps_variables),
	 sizeof(*v2authtraps_variables));
    }
    { static oid base[] = {SNMPSET};
      mib_register (base, 9, (struct variable *)setserno_variables,
	 sizeof(setserno_variables)/sizeof(*setserno_variables),
	 sizeof(*setserno_variables));
    }
    { static oid base[] = {USECAGENT};
      mib_register (base, 9, (struct variable *)usecagent_variables,
	 sizeof(usecagent_variables)/sizeof(*usecagent_variables),
	 sizeof(*usecagent_variables));
    }
    { static oid base[] = {USECSTATS};
      mib_register (base, 9, (struct variable *)usecstats_variables,
	 sizeof(usecstats_variables)/sizeof(*usecstats_variables),
	 sizeof(*usecstats_variables));
    }*/

}
#endif

/*
 * add an mib-entry to the subtrees list.
 * chain in at correct position.
 */

void
mib_register (oid_base, oid_base_len, mib_variables, 
	      mib_variables_len, mib_variables_width)
	oid *oid_base;
	int oid_base_len;
	struct variable *mib_variables;
	int mib_variables_len, mib_variables_width;
{
  struct subtree **sptr;
  struct subtree *new_subtree = TALLOC(struct subtree);
	debug(13,5)("snmp: registering new mib\n");
  if (! new_subtree) {
    fprintf (stderr, "error: registering mib: out of memory...aborting.\n");
    exit (1);
  }

  /*
   * fill in new subtree element:
   */
  memcpy (new_subtree->name, oid_base, oid_base_len * sizeof(oid));
  new_subtree->namelen = oid_base_len;
  new_subtree->variables = mib_variables;
  new_subtree->variables_len = mib_variables_len;
  new_subtree->variables_width = mib_variables_width;

  /* 
   * now hop along the subtrees and chain in: 
   */
  for (sptr = &subtrees; *sptr; sptr = &(*sptr)->next) {
    if (compare ((*sptr)->name, (*sptr)->namelen,
		 new_subtree->name, new_subtree->namelen) > 0) {
      break;
    }
  }
  new_subtree->next = *sptr;
  *sptr = new_subtree;
}

int
in_view(name, namelen, viewIndex)
    oid *name;
    int namelen, viewIndex;
{
    viewEntry *vwp, *savedvwp = NULL;
    extern viewEntry *views;

    for( vwp = views; vwp; vwp = vwp->next ) {
	if (vwp->viewIndex != viewIndex )
	    continue;
	if (vwp->viewSubtreeLen > namelen
	    || bcmp(vwp->viewSubtree, name, vwp->viewSubtreeLen * sizeof(oid)))
	    continue;
	/* no wildcards here yet */
	if (!savedvwp){
	    savedvwp = vwp;
	} else {
	    if (vwp->viewSubtreeLen > savedvwp->viewSubtreeLen)
		savedvwp = vwp;
	}
    }
    if (!savedvwp)
	return FALSE;
    if (savedvwp->viewType == VIEWINCLUDED)
	return TRUE;
    return FALSE;
}

/*
 * getStatPtr - return a pointer to the named variable, as well as it's
 * type, length, and access control list.
 *
 * If an exact match for the variable name exists, it is returned.  If not,
 * and exact is false, the next variable lexicographically after the
 * requested one is returned.
 *
 * If no appropriate variable can be found, NULL is returned.
 */
u_char	*
getStatPtr(oid 	  *name, 
	   int 	  *namelen, 
	   u_char *type, 
	   int    *len, 
	   u_short *acl, int exact, 
		SNMPWM **write_method,
		int snmpversion,
		int *noSuchObject,
		int view)
#ifdef HM_S
    oid		*name;	    /* IN - name of var, OUT - name matched */
    int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
    u_char	*type;	    /* OUT - type of matched variable */
    int		*len;	    /* OUT - length of matched variable */
    u_short	*acl;	    /* OUT - access control list */
    int		exact;	    /* IN - TRUE if exact match wanted */
    SNMPWM	**write_method; /* OUT - pointer to function called to set variable, otherwise 0 */
    int		 snmpversion;
    int		*noSuchObject;
    int		 view;*/
#endif
{
    struct subtree	*tp;
    struct variable *vp = 0;
    struct variable	compat_var, *cvp = &compat_var;
    int	x;
    u_char	*access = NULL;
    int			result, treeresult;
    oid 		*suffix;
    int			suffixlen;
    int 		found = FALSE;
    oid			save[MAX_NAME_LEN];
    int			savelen = 0;

    if( view == 0 ) 
	{
	debug(13,5)("snmp, No view found\n");
	return NULL;
	}
    if (!exact){
	bcopy(name, save, *namelen * sizeof(oid));
	savelen = *namelen;
    }
    *write_method = NULL;
    for (tp = subtrees; tp; tp = tp->next) {
	treeresult = compare_tree(name, *namelen, tp->name, (int)tp->namelen);
	/* if exact and treerresult == 0
	   if next  and treeresult <= 0 */
	if (treeresult == 0 || (!exact && treeresult < 0)){
	    result = treeresult;
	    suffixlen = *namelen - tp->namelen;
	    suffix = name + tp->namelen;
	    /* the following is part of the setup for the compatability
	       structure below that has been moved out of the main loop.
	     */
	    bcopy((char *)tp->name, (char *)cvp->name,
		  tp->namelen * sizeof(oid));

	    for(x = 0, vp = tp->variables; x < tp->variables_len;
		vp =(struct variable *)((char *)vp +tp->variables_width), x++){
		/* if exact and ALWAYS
		   if next  and result >= 0 */
		if (exact || result >= 0){
		    result = compare_tree(suffix, suffixlen, vp->name,
				     (int)vp->namelen);
		}
		/* if exact and result == 0
		   if next  and result <= 0 */
		if ((!exact && (result <= 0)) || (exact && (result == 0))){
		    /* builds an old (long) style variable structure to retain
		       compatability with var_* functions written previously.
		     */
		    bcopy((char *)vp->name, (char *)(cvp->name + tp->namelen),
			  vp->namelen * sizeof(oid));
		    cvp->namelen = tp->namelen + vp->namelen;
		    cvp->type = vp->type;
		    cvp->magic = vp->magic;
		    cvp->acl = vp->acl;
		    cvp->findVar = vp->findVar;
		    access = (*(vp->findVar))(cvp, name, namelen, exact,
						  len, write_method);
		    if (write_method)
			*acl = vp->acl;
		    if (access /*&& (snmpversion == SNMP_VERSION_2)*/
			&& !in_view(name, *namelen, view) ) {
			access = NULL;
			*write_method = NULL;
		    } else if (exact){
			found = TRUE;
		    }
		    /* this code is incorrect if there is
		       a view configuration that exludes a particular
		       instance of a variable.  It would return noSuchObject,
		       which would be an error */
		    if (access != NULL)
			break;
		}
		/* if exact and result <= 0 */
		if (exact && (result  <= 0)){
	            *type = vp->type;
		    *acl = vp->acl;
		    if (found)
			*noSuchObject = FALSE;
		    else
			*noSuchObject = TRUE;
			debug(13,5)("snmp: 523 return 0, nosuch=%d\n",
				*noSuchObject);
		    return NULL;
		}
	    }
	    if (access != NULL)
		break;
	}
    }
    if (! tp /* y == sizeof(subtrees)/sizeof(struct subtree) */ ){
	if (!access && !exact){
	    bcopy(save, name, savelen * sizeof(oid));
	    *namelen = savelen;
	}
	if (found)
	    *noSuchObject = FALSE;
	else
	    *noSuchObject = TRUE;
                        debug(13,5)("snmp: 541 return 0, nosuch=%d\n",
                                *noSuchObject);

        return NULL;
    }
    /* vp now points to the approprate struct */
    *type = vp->type;
    *acl = vp->acl;
	debug(13,5)("snmp: returning non null\n");
    return access;
}

/*
{
  *write_method = NULL;
  for(tp = first; tp < end; tp = next){
      if ((in matches tp) or (in < tp)){
	  inlen -= tp->length;
	  for(vp = tp->vp; vp < end; vp = next){
	      if ((in < vp) || (exact && (in == vp))){
		  cobble up compatable vp;
		  call findvar;
		  if (it returns nonzero)
		      break both loops;
	      }
	      if (exact && (in < vp)) ???
		  return NULL;
	  }
      }      
  }
}
*/

int
compare(name1, len1, name2, len2)
    oid	    *name1, *name2;
    int	    len1, len2;
{
    int    len;

#define cmpprintf	if(0) printf
    { int i;
      cmpprintf ("comparing ");
      for (i = 0; i < len1; i++)
	cmpprintf ("%ld%s", name1[i], i < len1 - 1 ? "." : "");
      cmpprintf (" with ");
      for (i = 0; i < len2; i++)
	cmpprintf ("%ld%s", name2[i], i < len2 - 1 ? "." : "");
    }

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2) {
	    cmpprintf (" giving -1\n");
	    return -1;
	}
	if (*name2++ < *name1++) {
	    cmpprintf (" giving 1\n");
	    return 1;
	}
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2) {
	cmpprintf (" giving -1\n");
	return -1;  /* name1 shorter, so it is "less" */
    }
    if (len2 < len1) {
	cmpprintf (" giving 1\n");
	return 1;
    }

    cmpprintf (" giving 0\n");

    return 0;	/* both strings are equal */
}

static int
compare_tree(name1, len1, name2, len2)
    oid	    *name1, *name2;
    int	    len1, len2;
{
    int    len;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2)
	    return -1;
	if (*name2++ < *name1++)
	    return 1;
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2)
	return -1;  /* name1 shorter, so it is "less" */
    /* name1 matches name2 for length of name2, or they are equal */
    return 0;
}



/* ../snmplib/snmp.c defines this without being if'defed */
char sysContact[256] = "Unknown";
char sysLocation[256] = "Unknown";
char sysName[256] = "Unknown";


oid version_id[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
