CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl -ltls
SRCS = certainty.c flatconf.c xlog.c util.c mdr.c mdr_mdrd.c
OBJS = config_vars.o xlog.o util.o mdr.o mdr_mdrd.o
YACC = yacc

all: certainty

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

certainty: certainty.c $(OBJS)
	${CC} ${CFLAGS} certainty.c ${LIBS} ${OBJS} -o certainty

clean:
	rm -f certainty *.o certainty.core core .depend flatconf.c
