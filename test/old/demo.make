# make -j2 -f demo.make clean all

$(shell echo 'int main(void){}' > prog.c)
$(shell touch common.in)

.PHONY: clean all

all: prog libcommon.so

clean:
	rm -f common.c prog libcommon.so

############################

# Should actually depend on prog.c *and common.c*
prog: prog.c
	gcc prog.c common.c -o prog

# Making this target will result in making common.c first
libcommon.so: common.c
	gcc -shared common.c -o libcommon.so

# common.c is generated in some way based on common.in
common.c: common.in
	ln common.in common.c
