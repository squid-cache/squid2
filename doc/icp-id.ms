.pl 10.0i
.po 0
.ll 7.2i
.lt 7.2i
.nr LL 7.2i
.nr LT 7.2i
.ds LF Wessels
.ds RF FORMFEED[Page %]
.ds CF
.ds LH Internet-Draft
.ds RH November 1996
.ds CH
.hy 0
.ad l
Network Working Group                                         D. Wessels
Internet-Draft                                   National Laboratory for
                                                Applied Network Research
                                                             August 1996
.sp 2
.ce
Internet Cache Protocol (ICP), version 2
.sp 2
.fi
.ne 4
Status of this Memo
.sp
.in 3

This document is an Internet-Draft. Internet-Drafts are working
documents of the Internet Engineering Task Force (IETF), its areas,
and its working groups. Note that other groups may also distribute
working documents as Internet-Drafts.

Internet-Drafts are draft documents valid for a maximum of six months
and may be updated, replaced, or obsoleted by other documents at any
time. It is inappropriate to use Internet-Drafts as reference
material or to cite them other than as ``work in progress.''

To learn the current status of any Internet-Draft, please check the
``1id-abstracts.txt'' listing contained in the Internet-Drafts Shadow
Directories on ftp.is.co.za (Africa), nic.nordu.net (Europe),
munnari.oz.au (Pacific Rim), ds.internic.net (US East Coast), or
ftp.isi.edu (US West Coast).


.sp
.in 0
.ne 4
Abstract
.sp
.in 3

This draft document describes the Internet Cache Protocol (ICP)
currently implemented in a few World-Wide Web proxy cache packages.
ICP was initially developed by Peter Danzig, et. al. at the 
Univerisity of Southern California.  It evolved as an important
part of hierarchical caching on the Harvest research project.

.sp
.in 0
.ne 4
Introduction
.sp
.in 3

ICP is a message format used for communicating between WWW caches.
ICP is primarily used in a cache mesh to locate specific 
WWW objects in neighbor caches.  One cache will send an ICP query
to its neighbors.  The neighbors will send back ICP replies indicating
a ``HIT'' or a ``MISS.''  ICP can also be used to multiplex transmission
of multiple object streams over a single TCP connection.

In current practice, ICP is implemented on top of UDP, but there
is no requirement that it be limited to UDP.  There are some functions
which work best over UDP, and others which work best over TCP.

In addition to it use as an object location protocol, the messages ICP
are often used for ``cache selection.''  Failure to receive a reply
from a cache may inidicate a network or system failure.  The order in
which the replies arrive may be used to select the ``closest''
neighbor.

.sp
.in 0
.ne 4
ICP Message Format
.sp
.in 3
.nf
 0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Opcode    |    Version    |        Message Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Request Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Options                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Padding                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sender Host Address                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                             |
|                            Payload                          |
/                                                             /
/                                                             /
|                                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
.fi

.in 3
NOTE: All fields must be represented in network byte order.

.in 3
Opcode
.in 6
One of the opcodes defined below.

.in 3
Version
.in 6
The ICP protocol version number.  At the time of this writing, both
versions two and three are in use.

.in 3
Message Length
.in 6
The total length of the ICP message.

.in 3
Request Number
.in 6
An opaque identifier.  When responding to a query, this value
must be copied into the reply message.

.in 3
Options
.in 6
A bitfield of options.  See ``ICP Options'' below.

.in 3
Padding
.in 6
Four bytes of padding; a legacy from previous versions.

.in 3
Sender Host Address
.in 6
The IPv4 address of the host sending the ICP message.  This field should
probably not be trusted over what is  provided by getpeername(), accept(),
and recvfrom().  There is some abmiguity over the original purpose of
this field.  In practice it is not used.

.in 3
Payload
.in 6
The contents of the Payload field vary depending on the Opcode, but
most often it contains a null-terminated URL string.


.sp
.in 0
.ne 4
ICP Opcodes
.sp

.in 3
.nf
Value    Name
-----    -----------------
    0    ICP_OP_INVALID
    1    ICP_OP_QUERY
    2    ICP_OP_HIT
    3    ICP_OP_MISS
    4    ICP_OP_ERR
    5    ICP_OP_SEND
    6    ICP_OP_SENDA
    7    ICP_OP_DATABEG
    8    ICP_OP_DATA
    9    ICP_OP_DATAEND
   10    ICP_OP_SECHO
   11    ICP_OP_DECHO
12-20    UNUSED
   21    ICP_OP_RELOADING
   22    ICP_OP_DENIED
   23    ICP_OP_HIT_OBJ
.fi

.in 3
ICP_OP_INVALID
.in 6
A placeholder to detect zero-filled or malformed messages.  ICP_OP_INVALID
must never be (intentionally) sent in a message.  ICP_OP_ERR should be
used instead.

.in 3
ICP_OP_QUERY
.in 6
A query message.  NOTE this opcode has a different payload format than
most of the others.  First is the requestor's IPv4 address, followed by
a URL.  The requestor address is often zero filled.

.nf
Payload Format:

 0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Requestor Host Address                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                             |
/                       Null-Terminated URL                   /
/                                                             /
|                                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
.fi

In response to an ICP_OP_QUERY, the receipient must return one of:
ICP_OP_HIT, ICP_OP_MISS, ICP_OP_ERR, ICP_OP_RELOADING, ICP_OP_DENIED,
or ICP_OP_HIT_OBJ.

.in 3
ICP_OP_SECHO
.in 6
Similar to ICP_OP_QUERY, but for use in simulating a query to 
an origin server.  When ICP is used to choose the closest neighbor,
the origin server can be included in the algorithm by bouncing
an ICP_OP_SECHO message off it's echo port.  The payload is 
simply the null-terminated URL.

NOTE: the echo server won't interpret the data (i.e. we could send it
anything).  This opcode is used to tell the difference between a
legitimate query or response, random garbage, and an echo response.

.in 3
ICP_OP_DECHO
.in 6
Similar to ICP_OP_QUERY, but for use in simulating a query to an cache
which does not use ICP.  When ICP is used to choose the closest
neighbor, a non-ICP cache can be included in the algorithm by bouncing
an ICP_OP_DECHO message off it's echo port.  The payload is 
simply the null-terminated URL.

NOTE: one problem with this approach is that while a system's
echo port may be functioning perfectly, the cache software may
not be running at all.

.sp
.in 3
One of the following six ICP opcodes are sent in response to an
ICP_OP_QUERY message.  For each one the payload must be the
null-terminated URL string.  Both
the URL string and the Request Number field must be exactly the same
as from the ICP_OP_QUERY message.

.in 3
ICP_OP_HIT
.in 6
Sending an ICP_OP_HIT
response indicates that the requested URL exists in this cache.

.in 3
ICP_OP_MISS
.in 6
Sending an ICP_OP_MISS
response indicates that the requested URL does not exist in this
cache.

.in 3
ICP_OP_ERR
.in 6
Sending an ICP_OP_ERR indicates some kind of
error in parsing or handling the query message.

.in 3
ICP_OP_RELOADING
.in 6
Sending an ICP_OP_RELOADING
response indicates that this cache is up, but is in a ``startup'' mode.
A cache in startup mode may wish to return ICP_OP_HIT for cache hits,
but not ICP_OP_MISS for misses.  ICP_OP_RELOADING essentially means
``I am up and running, but please don't fetch this URL from me now.''

.in 3
ICP_OP_DENIED
.in 6
Sending an
ICP_OP_DENIED response indicates that the querying site is not
allowed to retrieve the named object from this cache.  Caches
and proxies may implement complex access controls.  This reply
can only be interpreted to mean ``you are not allowed to request
this particular URL from me at this particular time.''

.in 3
ICP_OP_HIT_OBJ
.in 6
Just like an ICP_OP_HIT response, but the actual object data has
been included in this reply message.   Many requested objects are 
small enough that it makes sense to include them in the query
response and avoid the need to make a subsequent HTTP request
for the object.

An ICP_OP_HIT_OBJ reply will be sent only if the ICP_FLAG_HIT_OBJ
flag is set in the query message Options field.

.nf
Payload Format:

 0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                             |
/                       Null-Terminated URL                   /
/                                                             /
|                                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Object Size           |                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                             |
|                                                             |
/                          Object Data                        /
/                                                             /
|                                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
.fi

The protocol does not impose any limits on the maximum size of 
the Object Data.  Software that the author is familiar with will
use ICP_OP_HIT_OBJ over ICP_OP_HIT if the entire message is less than
the system's maximum UDP transmission size.

The receiving application should check to make sure it actually 
receives Object Size bytes of data.  If it does not, then it should
treat the ICP_OP_HIT_OBJ reply as though it were a normal ICP_OP_HIT.

NOTE: the Object Size field does not necessarily begin on a
32-bit boundary as shown in the diagram above.  It begins immediately
following the NULL byte of the URL string.

.in 3
The following six opcodes have historically been used for experimenting
with multiplexing object transmission over a TCP connection.  At the
time of this writing, there are no functional proxy/cache
implementations using these opcodes.  They are only mentioned here
because they still exist in some source code.  Any future implementations
of cache-cache multiplexing will likely need to redefine these.

.in 3
ICP_OP_SEND
.in 6
Request for object data (non authoritative).

.in 3
ICP_OP_SENDA
.in 6
Request for object data (authoritative).

.in 3
ICP_OP_DATABEG
.in 6
Beginning of data transmission.

.in 3
ICP_OP_DATA
.in 6
Middle of data transmission.

.in 3
ICP_OP_DATAEND
.in 6
End of data transmission.





.sp
.in 0
.ne 4
ICP Options
.sp

.in 3
0x80000000  ICP_FLAG_HIT_OBJ
This flag is set in an ICP_OP_QUERY message indicating that it is
okay to respond with an ICP_OP_HIT_OBJ message if the object data
will fit.


.sp
.in 0
Missing Features
.sp
.in 3
Note the lack of an HTTP method in the ICP query.  The current version
can only be used for GET requests.

.sp
.in 0
Security Considerations
.sp
.in 3
Security is an issue with ICP over UDP because of its connectionless
nature.  A proxy/cache must only process ICP messages received
from its known neighbors.  Messages from unknown addresses must be
discarded. 

The ICP_OP_HIT_OBJ message is especially senstive to security issues since
it contains actual object data in the response.  In combination with 
IP spoofing it is most likely possible to pollute the cache with
invalid objects.

.in 0
.ne 5
Author's  Address:
.sp
.in 3
.nf
Duane Wessels
National Laboratory for Applied Network Research
wessels@nlanr.net

K Claffy
National Laboratory for Applied Network Research
kc@nlanr.net

.fi
.sp
.in 0
