PRG=Squid

FILENAME=`basename ${PRG}-*.pkg`

pkg:
	./makepkg

tar: pkg
	gnutar zcvf ${FILENAME}.tar.gz ${FILENAME} ${FILENAME}.README

clean:
	rm -rf ${FILENAME} ${FILENAME}.tar.gz ${FILENAME}.README
