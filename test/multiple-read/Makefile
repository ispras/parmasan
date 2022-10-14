.PHONY: all clean create append read_1 read_2 rm

all: create append read_1 read_2 rm

create:
	echo "hi" > a

append: create
	echo " there" >> a

read_1: create
	cat a

read_2: create
	cat a

rm: create # read_1 and read_2 dependencies are missing
	rm a

clean:
	rm -f a
