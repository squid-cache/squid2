#
#  Makefile for the Squid SASL authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/

libexec_PROGRAMS	= sasl_auth
LDADD			= -lsasl $(XTRA_LIBS)
