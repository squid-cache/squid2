#ifndef _SQUID_SNMP_OID_LIST_H_
#define _SQUID_SNMP_OID_LIST_H_

/* Function called to parse an OID */
typedef variable_list *(oid_ParseFn)(variable_list *, snint *);

/* Function called when looking for an OID in a MIB */
typedef oid_ParseFn *(oid_GetFn)(oid *, snint);

/* Function called when looking for the next OID in a MIB */
typedef oid_ParseFn *(oid_GetNextFn)(oid *, snint, oid **, snint *);

/* Find things in the master oidlist */
oid_ParseFn *oidlist_Find(oid *, snint);
oid_ParseFn *oidlist_Next(oid *, snint, oid **, snint *);

void print_oid(oid *, snint);
int  oidcmp(oid *, snint, oid *, snint);
oid *oiddup(oid *, snint);

struct OidListEntry {
  oid          Name[1];
  snint         NameLen;
  oid_ParseFn *ParseFn;
};


#endif /* _SQUID_SNMP_OID_LIST_H_ */

