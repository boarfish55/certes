CC = cc
EXTRA_CFLAGS =
VERSION = 0.4.8
CFLAGS = -Wall -g ${EXTRA_CFLAGS} \
	 `pkg-config --cflags libcrypto libssl mdr flatconf sqlite3`
LDFLAGS = `pkg-config --libs libcrypto libssl mdr flatconf sqlite3`
SRCS = certes.c util.c certdb.c mdr_certes.c authority.c cert.c agent.c
OBJS = util.o certdb.o mdr_certes.o authority.o cert.o agent.o

all: certes

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

certes: certes.c $(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} certes.c ${LIBS} ${OBJS} -o certes

clean:
	rm -f certes *.o certes.core core .depend
