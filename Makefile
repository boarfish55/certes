CC = cc
CFLAGS = -Wall -g -I/usr/local/include
LDFLAGS = -L/usr/local/lib
LIBS = -lcrypto -lssl -ltls -lsqlite3
SRCS = certalator.c flatconf.c xlog.c util.c mdr.c mdr_mdrd.c \
       certdb.c mdr_certalator.c authority.c cert.c agent.c
OBJS = flatconf.o xlog.o util.o mdr.o mdr_mdrd.o certdb.o mdr_certalator.o\
	authority.o cert.o agent.o
YACC = yacc

all: certalator

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

certalator: certalator.c $(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} certalator.c ${LIBS} ${OBJS} -o certalator

clean:
	rm -f certalator *.o certalator.core core .depend flatconf.c
