#!/bin/sh
if [ "$1" == "HEIMDAL" ]; then
  DEFINE=-DHEIMDAL
  INCLUDE=-I/usr/include/heimdal -Ispnegohelp
  LIBS="-lgssapi -lkrb5 -lcom_err -lasn1 -lroken"
else
#MIT
  DEFINE=
  INCLUDE=-Ispnegohelp
  LIBS="-lgssapi_krb5 -lkrb5 -lcom_err"
fi
SPNEGO="spnegohelp/derparse.c  spnegohelp/spnego.c  spnegohelp/spnegohelp.c  spnegohelp/spnegoparse.c"
SOURCE="squid_kerb_auth.c base64.c"
gcc -o squid_kerb_auth $DEFINE $INCLUDE $SOURCE $SPNEGO $LIBS
