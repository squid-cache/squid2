PRG=Squid

FILENAME=`basename ${PRG}-*.pkg`

${FILENAME}:
	./makepkg
	cp -p Squid.README ${FILENAME}.README

tar: ${FILENAME}
	gnutar zcvf ${FILENAME}.tar.gz ${FILENAME} ${FILENAME}.README

clean:
	rm -rf ${FILENAME} ${FILENAME}.tar.gz ${FILENAME}.README
