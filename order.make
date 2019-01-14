.PHONY: clean

a: clean b c # The order of prerequisites is important here; this is a race
	cat $(realpath $^) > $@

b:
	echo "hi" | tee b > m

c:
	cat m > c

clean:
	rm -f a b c m
