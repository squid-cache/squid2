# Makefile for smb_auth

# SAMBAPREFIX must point to the directory where Samba has been installed.
# By default, Samba is installed in /usr/local/samba. If you changed this
# by using the --prefix option when configuring Samba, you need to change
# SAMBAPREFIX accordingly.

SAMBAPREFIX=/usr/local/samba

# INSTALLBIN is the directory in which both smb_auth and its helper script
# smb_auth.sh, will be installed. smb_auth uses this value to find its
# helper script, so change this before compiling smb_auth.

INSTALLBIN=/usr/local/bin

# End of configuration section

OBJECTS = smb_auth.o
SCRIPT  = smb_auth.sh

CC      = gcc
CFLAGS  = -O2 -Wall \
	  -DSAMBAPREFIX=\"$(SAMBAPREFIX)\" -DHELPERSCRIPT=\"$(INSTALLBIN)/$(SCRIPT)\"

smb_auth: $(OBJECTS)
	$(CC) -o smb_auth $(OBJECTS)

install: smb_auth
	install smb_auth $(SCRIPT) $(INSTALLBIN)

clean:
	rm -f smb_auth $(OBJECTS)
