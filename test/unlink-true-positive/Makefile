.PHONY: all clean create read rm_a rm_b

all: create read rm_a rm_b

create:
	echo "hi" > a
	ln a b

read: create
	cat a

rm_a: create # read dependency is missing
	rm a

rm_b: create read
	rm b

clean:
	rm -f a b
