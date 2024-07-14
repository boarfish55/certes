CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl -ltls
SRCS = certainty.c config_vars.c xlog.c util.c mdr.c mdr_mdrd.c
OBJS = config_vars.o xlog.o util.o mdr.o mdr_mdrd.o

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
