
struct _HierarchyLogEntry {
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    icp_ping_data icp;
};

struct _AccessLogEntry {
    const char *url;
    struct {
	method_t method;
	int code;
	const char *content_type;
    } http;
    struct {
	icp_opcode opcode;
    } icp;
    struct {
	struct in_addr caddr;
	size_t size;
	log_type code;
	int msec;
	const char *ident;
    } cache;
    HierarchyLogEntry hier;
    struct {
	char *request;
	char *reply;
    } headers;
    struct {
	const char *method_str;
    } private;
};


extern void accessLogLog _PARAMS((AccessLogEntry *));
extern void accessLogRotate _PARAMS((void));
extern void accessLogClose _PARAMS((void));
extern void accessLogOpen _PARAMS((const char *));
extern void hierarchyNote _PARAMS((HierarchyLogEntry *, hier_code, icp_ping_data *, const char *));
