.PHONY: clean

all: all.sufout

.SUFFIXES: .sufin .sufout

.sufin.sufout:
	cat $< > $@

clean:
	rm -f all.sufout
