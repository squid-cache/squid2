
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

typedef enum {
    MGR_NONE,
    MGR_CLIENT_LIST,
    MGR_CONFIG,
    MGR_CONFIG_FILE,
    MGR_DNSSERVERS,
    MGR_FILEDESCRIPTORS,
    MGR_FQDNCACHE,
    MGR_INFO,
    MGR_IO,
    MGR_IPCACHE,
    MGR_LOG_CLEAR,
    MGR_LOG_DISABLE,
    MGR_LOG_ENABLE,
    MGR_LOG_STATUS,
    MGR_LOG_VIEW,
    MGR_NETDB,
    MGR_OBJECTS,
    MGR_REDIRECTORS,
    MGR_REFRESH,
    MGR_REMOVE,
    MGR_REPLY_HDRS,
    MGR_SERVER_LIST,
    MGR_SHUTDOWN,
    MGR_UTILIZATION,
    MGR_VM_OBJECTS,
    MGR_STOREDIR,
    MGR_CBDATA,
    MGR_MAX
} objcache_op;

static char *objcacheOpcodeStr[] =
{
    "NONE",
    "client_list",
    "config",
    "config_file",
    "dnsservers",
    "filedescriptors",
    "fqdncache",
    "info",
    "io",
    "ipcache",
    "log/clear",
    "log/disable",
    "log/enable",
    "log/status",
    "log/view",
    "netdb",
    "objects",
    "redirectors",
    "refresh",
    "remove",
    "reply_headers",
    "server_list",
    "shutdown",
    "utilization",
    "vm_objects",
    "storedir",
    "cbdata",
    "MAX"
};
