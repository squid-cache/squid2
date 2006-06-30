DOC	= release-2.6

all: html

.PHONY: html ps

html: $(DOC).html
ps: $(DOC).ps

$(DOC).ps: $(DOC).sgml
	linuxdoc -B latex -o ps $(DOC)

#$(DOC).dvi: $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#	latex $(DOC).tex
#

$(DOC).txt: $(DOC).sgml
	linuxdoc -B txt -T 2 --filter $(DOC)

$(DOC).html: $(DOC).sgml
	linuxdoc -B html -T 2 --split=0 $(DOC)

$(DOC).man: $(DOC).sgml
	linuxdoc -B txt -m $(DOC)

clean:
	rm -f *.html
	rm -f $(DOC).tex $(DOC).ps $(DOC).dvi $(DOC).aux $(DOC).log $(DOC).toc
	rm -f $(DOC).txt $(DOC).man
