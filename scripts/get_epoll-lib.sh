#!/bin/bash

set -e

EPOLL_URL="http://www.xmailserver.org/linux-patches/epoll-lib-0.11.tar.gz"
EPOLL_FILE="epoll-lib-0.11.tar.gz"
EPOLL_DIR="epoll-lib-0.11"

KERNELSOURCE=$1

if [ "$0" != "./scripts/get_epoll-lib.sh" ]
then
	echo
	echo "You must run this program from the root squid source directory"
	echo "ie /usr/src/squid-2.5.STABLE9"
	echo "to run type:"
	echo
	echo "sh ./scripts/get_epoll-lib.sh"
	echo
	echo
	echo
	exit -1;
fi

if [ ! -f $EPOLL_FILE ]
then
	if [ ! -x "`which wget`" ]
	then
		echo
		echo "This script uses wget to download the source file"
		echo "Please either install wget, or download libepoll from:"
		echo "$EPOLL_URL"
		echo
		echo
		echo
		exit -1
	fi

	wget $EPOLL_URL
fi

if [ ! -d $EPOLL_DIR ]
then
	tar -zxvf $EPOLL_FILE
fi

pushd $EPOLL_DIR
	set +e
	if [ -z "$KERNELSOURCE" ]
	then
		make lib/libepoll.a PREFIX=..
	else
		make lib/libepoll.a PREFIX=.. KERNELDIR=$KERNELSOURCE
	fi

	if [ $? -ne 0 ]
	then
		echo
		echo "epoll make failed"
		echo "You may need to run $0 /usr/src/linux-2.6"
		echo "(or give the correct path to a 2.6 kernel source)"
		echo
		popd
		exit -1
	fi

	if [ ! -d ../include/sys ]
	then
		set -e
		mkdir ../include/sys
		set +e
	fi

	make install PREFIX=.. 2>/dev/null
popd

