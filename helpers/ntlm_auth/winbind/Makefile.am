#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#

libexec_PROGRAMS = wb_ntlmauth
wb_ntlmauth_SOURCES = wb_ntlm_auth.c wb_common.c samba_nss.h wbntlm.h winbind_nss_config.h
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src
LDADD = -L$(top_builddir)/lib -lmiscutil -lntlmauth -lm
