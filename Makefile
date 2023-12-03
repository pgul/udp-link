CC=gcc
SRCS=udp-link.c network.c log.c
OBJS=${SRCS:.c=.o}
CFLAGS=-Wall -O2 -ggdb

all: udp-link

udp-link: $(OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS)

*.o:	Makefile udp-link.h

.c.o:
	$(CC) -c $(COPT) -o $@ $<

