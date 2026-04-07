CC = cc
CFLAGS = -Wall -g -I/usr/local/include
LDFLAGS = -L/usr/local/lib
LIBS = -lcrypto -lssl -ltls -lsqlite3
SRCS = certes.c flatconf.c xlog.c util.c mdr.c mdr_mdrd.c \
       certdb.c mdr_certes.c authority.c cert.c agent.c
OBJS = flatconf.o xlog.o util.o mdr.o mdr_mdrd.o certdb.o mdr_certes.o\
	authority.o cert.o agent.o
YACC = yacc

all: certes

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

certes: certes.c $(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} certes.c ${LIBS} ${OBJS} -o certes

clean:
	rm -f certes *.o certes.core core .depend flatconf.c
