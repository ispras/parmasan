PDFLATEX=xelatex
BIBTEX=bibtex

all: parmasan-intro-slides.pdf

%.pdf: %.tex
	$(PDFLATEX) $<

parmasan-intro-slides.pdf: demo.pdf

demo.pdf: demo.dot
	dot -Tpdf $< > $@

clean:
	rm -f *.out *.aux *.log *.snm *.nav *.toc *.vrb $(OUT)

.PHONY: all clean
