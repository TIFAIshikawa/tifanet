CC	?=cc
LD	?=cc
DESTDIR	?=/usr/local
#CFLAGS	+=-g -Wall
CFLAGS	+=-g -Wall -Wmissing-prototypes -Wstrict-prototypes
LDFLAGS	+=-lsodium

BASENAME=tifa

SRCS	=config.c base64.c error.c pact.c txcache.c cache.c wallet.c network.c opcode_callback.c notar.c keypair.c address.c block.c event.c node.c log.c lock.c

DSRCS	=main-daemon.c $(SRCS)
DOBJS	=$(DSRCS:.c=.o)
DAEMON	=$(BASENAME)netd

CSRCS	=main-cli.c $(SRCS)
COBJS	=$(CSRCS:.c=.o)
CLI	=$(BASENAME)

.c.o:
	$(CC) -o $@ $(CFLAGS) -c $<

all:	$(DAEMON) $(CLI)

$(DAEMON): config.h $(DOBJS)
	$(CC) -o $(DAEMON) $(DOBJS) $(LDFLAGS)

$(CLI): config.h $(COBJS)
	$(CC) -o $(CLI) $(COBJS) $(LDFLAGS)

install-daemon: $(DAEMON)
	install -D $(DESTDIR)/sbin tifanetd

install-cli: $(CLI)
	install -D $(DESTDIR)/bin tifa

install-man:
	mkdir -p $(DESTDIR)/man/man{1,7,8}
	install -D $(DESTDIR)/man/man1 man/man1/tifa.1
	install -D $(DESTDIR)/man/man7 man/man7/tifa.7
	install -D $(DESTDIR)/man/man8 man/man7/tifa.8

install: install-daemon install-cli install-man

clean:
	rm -f $(DAEMON) $(CLI) $(DOBJS) $(COBJS) *.core .depend

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $(SRCS) > ./.depend

-include .depend
