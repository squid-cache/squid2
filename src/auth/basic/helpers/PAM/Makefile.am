#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		  -I$(top_srcdir)/src/

man_MANS	= pam_auth.8
libexec_PROGRAMS	= pam_auth
LDADD			= -lpam $(XTRA_LIBS)
