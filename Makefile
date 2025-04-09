CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl -ltls
SRCS = certalator.c flatconf.c xlog.c util.c mdr.c mdr_mdrd.c certdb.c
OBJS = config_vars.o xlog.o util.o mdr.o mdr_mdrd.o
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
	${CC} ${CFLAGS} certalator.c ${LIBS} ${OBJS} -o certalator

clean:
	rm -f certalator *.o certalator.core core .depend flatconf.c
