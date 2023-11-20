CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl
OBJS = config_vars.o xlog.o

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

xlog.o: xlog.c
	$(CC) $(CFLAGS) xlog.c -c -o xlog.o

config_vars.o: config_vars.c
	$(CC) $(CFLAGS) config_vars.c -c -o config_vars.o

certainty: certainty.c config_vars.o xlog.o
	$(CC) $(CFLAGS) certainty.c $(LIBS) $(OBJS) -o certainty

clean:
	rm -f certainty *.o certainty.core core
