CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g -static-pie
LDFLAGS = -static-pie

PROGS = runner

all:$(PROGS)

%.o: %.c
	$(CXX) -c $(CFLAGS)  $<

runner: runner.o 
	$(CXX) -o $@ $^ $(LDFLAGS) 

run: 
	./runner ./sample1
clean:
	rm -f *.o *~ $(PROGS)
	