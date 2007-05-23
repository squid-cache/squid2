#!/bin/sh
#
# Linux:
# -D__LITTLE_ENDIAN__
# Solaris:
# -D__BIG_ENDIAN__
#
if [ "$1" == "HEIMDAL" ]; then
  DEFINE="-DHEIMDAL -D__LITTLE_ENDIAN__"
  INCLUDE="-I/usr/include/heimdal -Ispnegohelp"
  LIBS="-lgssapi -lkrb5 -lcom_err -lasn1 -lroken"
else
#MIT
  DEFINE="-D__LITTLE_ENDIAN__"
  INCLUDE=-Ispnegohelp
  LIBS="-lgssapi_krb5 -lkrb5 -lcom_err"
fi
SPNEGO="spnegohelp/derparse.c  spnegohelp/spnego.c  spnegohelp/spnegohelp.c  spnegohelp/spnegoparse.c"
SOURCE="squid_kerb_auth.c base64.c"
gcc -g -o squid_kerb_auth $DEFINE $INCLUDE $SOURCE $SPNEGO $LIBS
