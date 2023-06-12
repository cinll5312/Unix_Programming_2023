CC		= gcc
CFLAGS	= -Wall -g 
LDFLAGS =
PROGS	= solver_sample

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

solver_sample: solver_sample.o
	$(CC) -o $@ $^