# Generated automatically from Makefile.in by configure.
# $Id$
#
prefix		= /local/squid-1.2
exec_prefix	= ${prefix}
top_srcdir	= ..
bindir		= ${exec_prefix}/bin
libexecdir      = ${bindir}
sysconfdir	= ${prefix}/etc
localstatedir   = ${prefix}
srcdir		= .
SH		= /usr/bin/sh
RM		= /usr/bin/rm
SHELL		= /usr/bin/sh

INSTALL         	= ../aux/install-sh -c
INSTALL_FILE    	= ${INSTALL} -m 644
DEFAULT_ERROR_DIR	= $(sysconfdir)/errors

LANGUAGE		= English

all:

install: install-mkdirs
	@for f in $(LANGUAGE)/ERR_*; do \
		if test -f $(DEFAULT_ERROR_DIR)/$$f ; then \
			:; \
		else \
			echo "$(INSTALL_FILE) $$f $(DEFAULT_ERROR_DIR)"; \
			$(INSTALL_FILE) $$f $(DEFAULT_ERROR_DIR); \
		fi \
	done

install-mkdirs:
	-@if test ! -d $(prefix); then \
		echo "mkdir $(prefix)"; \
		mkdir $(prefix); \
	fi
	-@if test ! -d $(sysconfdir); then \
		echo "mkdir $(sysconfdir)"; \
		mkdir $(sysconfdir); \
	fi
	-@if test ! -d $(DEFAULT_ERROR_DIR); then \
		echo "mkdir $(DEFAULT_ERROR_DIR)"; \
		mkdir $(DEFAULT_ERROR_DIR); \
	fi

clean:

