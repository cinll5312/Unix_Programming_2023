CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g 
LDFLAGS = -lcapstone
LIBNAME = $(shell pwd)/capstone/include
#-l$(shell pwd)/capstone/include -l$(shell pwd)/capstone/lib64 -lcapstone
PROGS = sdb

all:$(PROGS)
#-I$(LIBNAME)
%.o: %.c
	$(CXX) -c $(CFLAGS)  -I$(LIBNAME) $<

sdb: sdb.o
	$(CXX) -o $@ $^ $(LDFLAGS) -I$(LIBNAME)
san:
	g++ -fsanitize=address -g -o sdb sdb.c -lcapstone
run: 
	./sdb ./hello64
hel:
	./sdb ./hello
gus:
	./sdb ./guess
clean:
	rm -f *.o *~ $(PROGS)
	