CC = cc
CFLAGS = -Wall -g
LIBS = -lcrypto -lssl

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

certainty: certainty.c
	$(CC) $(CFLAGS) certainty.c $(LIBS) -o certainty

clean:
	rm -f certainty *.o certainty.core core
