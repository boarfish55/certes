CC = cc
DEPDIR = .deps
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl
OBJS = config_vars.o xlog.o util.o

OS != uname -s

.if ${OS} == "OpenBSD"
LIBS += -ltls
.else
PKGCONFIG_LIBS != pkg-config --libs libbsd-overlay libbsd-ctor
PKGCONFIG_CFLAGS != pkg-config --cflags libbsd-overlay libbsd-ctor
CFLAGS += $(PKGCONFIG_CFLAGS) -fstack-protector-strong
LIBS += $(PKGCONFIG_LIBS) -Wl,-z,relro -Wl,-z,now
.endif

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
