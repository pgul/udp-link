CC=gcc
SRCS=udp-link.c network.c log.c
OBJS=${SRCS:.c=.o}
CFLAGS=-Wall -O2 -ggdb

all:	udp-link

clean:
	rm -f *.o udp-link

install:
	if [ -d /opt/local/bin ]; then dst_dir=/opt/local/bin; else dst_dir=/usr/local/bin; fi; \
	install -m 755 udp-link $$dst_dir

udp-link: $(OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS)

*.o:	Makefile udp-link.h

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
