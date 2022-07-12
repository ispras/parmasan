PHONY: clean

a: clean b c
	cat $(realpath $^) > $@

b:
	echo "hi" | tee b > m

c: b
	cat m > c

clean:
	rm -f a b c m
