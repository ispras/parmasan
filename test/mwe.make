$(shell echo 'int main(){}' > a.c)

clean:
	rm a.out

a.out: clean
	gcc a.c
