.PHONY: clean all

all: all.sufout

.SUFFIXES: .sufin .sufint .sufout

.sufin.sufint:
	cat $< > $@

.sufint.sufout:
	cat $< > $@

clean:
	rm -f all.sufout all.sufint
