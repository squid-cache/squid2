.SUFFIXES: .pkg .tar .info

VERSION=`pwd | sed 's"/contrib/nextstep""' | sed 's/.*-//'`

pkg:
	${MAKE} -f Makefile.real VERSION=${VERSION} pkg

tar:
	${MAKE} -f Makefile.real VERSION=${VERSION} tar

clean:
	${MAKE} -f Makefile.real VERSION=${VERSION} clean

