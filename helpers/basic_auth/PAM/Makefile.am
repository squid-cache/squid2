#
#  Makefile for the Squid PAM authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/

libexec_PROGRAMS	= pam_auth
LDADD			= -lpam $(XTRA_LIBS)
