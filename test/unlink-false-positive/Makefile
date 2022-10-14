.PHONY: all clean create rm_a rm_b

all: create rm_a rm_b

create:
	echo "hi" > a
	ln a b

rm_a: create
	rm a

rm_b: create
	rm b

clean:
	rm -f a b
