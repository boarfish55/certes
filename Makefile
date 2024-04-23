CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl -ltls
SRCS = certainty.c config_vars.c xlog.c util.c
OBJS = config_vars.o xlog.o util.o

depend:
	mkdep $(CFLAGS) $(SRCS)

all: certainty

util.o: util.c util.h
	$(CC) $(CFLAGS) util.c -c -o util.o

xlog.o: xlog.c xlog.h
	$(CC) $(CFLAGS) xlog.c -c -o xlog.o

config_vars.o: config_vars.c
	$(CC) $(CFLAGS) config_vars.c -c -o config_vars.o

certainty: certainty.c $(OBJS)
	$(CC) $(CFLAGS) certainty.c $(LIBS) $(OBJS) -o certainty

clean:
	rm -f certainty *.o certainty.core core
