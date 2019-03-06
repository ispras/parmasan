.PHONY: clean all

b:
	echo hi > $@

depend:
	echo "all: b" > depend

clean:
	rm -f b
	rm depend # It is included and remade on `make clean` invocation as well.

include depend
