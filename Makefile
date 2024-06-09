CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl -ltls
SRCS = certainty.c config_vars.c xlog.c util.c tlsev.c idxheap.c mdr.c \
       mdr_certainty.c
OBJS = config_vars.o xlog.o util.o tlsev.o idxheap.o mdr.o mdr_certainty.o

all: certainty

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

certainty: certainty.c $(OBJS)
	${CC} ${CFLAGS} certainty.c ${LIBS} ${OBJS} -o certainty

clean:
	rm -f certainty *.o certainty.core core .depend
