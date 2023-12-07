CC=gcc
SRCS=udp-link.c network.c log.c
OBJS=${SRCS:.c=.o}
CFLAGS=-Wall -O2 -ggdb

all:	udp-link

clean:
	rm -f *.o udp-link

install:
	install -m 755 udp-link /usr/local/bin

udp-link: $(OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS)

*.o:	Makefile udp-link.h

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
