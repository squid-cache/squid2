/*
 * $Id$
 */

struct MIBListEntry squidMIBList[] =
{
    {
	{SQ_SYS}, LEN_SQ_SYS, sysGetFn, sysGetNextFn},
    {
	{SQ_CONF}, LEN_SQ_CONF, confGetFn, confGetNextFn},
    {
	{SQ_CONF, 6}, LEN_SQ_CONF + 1, confGetFn, confStGetNextFn},
    {
	{SQ_PRF, 1}, LEN_SQ_PRF + 1, prfSysGetFn, prfSysGetNextFn},
    {
	{SQ_PRF, 2}, LEN_SQ_PRF + 1, prfProtoGetFn, prfProtoGetNextFn},
    {
        {SQ_NET, 1}, LEN_SQ_NET + 1, netIpGetFn, netIpGetNextFn},
    {
        {SQ_NET, 2}, LEN_SQ_NET + 1, netFqdnGetFn, netFqdnGetNextFn},
    {
        {SQ_NET, 3}, LEN_SQ_NET + 1, netDnsGetFn, netDnsGetNextFn},
    {
	{SQ_MESH, 1}, LEN_SQ_MESH + 1, meshGetFn, meshPtblGetNextFn},
    {
	{SQ_MESH, 2}, LEN_SQ_MESH + 1, meshGetFn, meshCtblGetNextFn},
    {
	{0}, 0, NULL, NULL}
};
