struct MIBListEntry squidMIBList[] =
{
    {
	{SYSMIB}, LEN_SYSMIB, basicGetFn, basicGetNextFn},
    {
	{SQ_SYS}, LEN_SQ_SYS, sysGetFn, sysGetNextFn},
    {
	{SQ_SYS, 3}, LEN_SQ_SYS + 1, sysConnGetFn, sysConnGetNextFn},
    {
	{SQ_SYS, 4}, LEN_SQ_SYS + 1, sysFdGetFn, sysFdGetNextFn},
    {
	{SQ_CONF}, LEN_SQ_CONF, confGetFn, confGetNextFn},
    {
	{SQ_CONF, 6}, LEN_SQ_CONF + 1, confGetFn, confStGetNextFn},
    {
	{SQ_PRF, 1}, LEN_SQ_PRF + 1, prfSysGetFn, prfSysGetNextFn},
    {
	{SQ_PRF, 2}, LEN_SQ_PRF + 1, prfProtoGetFn, prfProtoGetNextFn},
    {
	{SQ_NET, 1}, LEN_SQ_NET + 1, netdbGetFn, netdbGetNextFn},
    {
	{SQ_NET, 2}, LEN_SQ_NET + 1, dnsGetFn, dnsGetNextFn},
    {
	{SQ_MESH, 1}, LEN_SQ_MESH + 1, meshGetFn, meshPtblGetNextFn},
    {
	{SQ_MESH, 2}, LEN_SQ_MESH + 1, meshGetFn, meshCtblGetNextFn},
    {
	{0}, 0, NULL, NULL}
};
