
/*
 * $Id$
 *
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  
 */

static char *objcacheOpcodeStr[] =
{
    "NONE",
    "client_list",
    "config",
    "dnsservers",
    "filedescriptors",
    "fqdncache",
    "info",
    "io",
    "ipcache",
    "log_clear",
    "log_disable",
    "log_enable",
    "log_status",
    "log_view",
    "netdb",
    "objects",
    "redirectors",
    "refresh",
    "remove",
    "reply_headers",
    "server_list",
    "non_peers",
    "shutdown",
    "utilization",
    "vm_objects",
    "storedir",
    "cbdata",
    "pconn",
    "MAX"
};
