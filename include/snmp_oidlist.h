#ifndef _SQUID_SNMP_OID_LIST_H_
#define _SQUID_SNMP_OID_LIST_H_

/* Function called to parse an OID */
typedef variable_list *(oid_ParseFn)(variable_list *, long *);

/* Function called when looking for an OID in a MIB */
typedef oid_ParseFn *(oid_GetFn)(oid *, long);

/* Function called when looking for the next OID in a MIB */
typedef oid_ParseFn *(oid_GetNextFn)(oid *, long, oid **, long *);

/* Find things in the master oidlist */
oid_ParseFn *oidlist_Find(oid *, long);
oid_ParseFn *oidlist_Next(oid *, long, oid **, long *);

void print_oid(oid *, long);
int  oidcmp(oid *, long, oid *, long);
oid *oiddup(oid *, long);

struct OidListEntry {
  oid          Name[1];
  long         NameLen;
  oid_ParseFn *ParseFn;
};


#endif /* _SQUID_SNMP_OID_LIST_H_ */

