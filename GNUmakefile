CC := gcc
VERSION = 0.5.14
DEPDIR := .deps
# Project-mandatory flags. We *append* to CFLAGS/CPPFLAGS/LDFLAGS so that any
# flags supplied through the environment (notably dpkg-buildflags under Debian:
# hardening, -O2, -D_FORTIFY_SOURCE, -ffile-prefix-map, ...) are preserved
# instead of being clobbered.
CFLAGS += -Wall -g -fstack-protector-strong -DOPENSSL_API_COMPAT=0x10101000L \
	  -fstack-clash-protection -fcf-protection \
	  $(shell pkg-config --cflags libbsd-overlay libbsd-ctor mdr flatconf)
LDFLAGS += $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	   libcrypto libssl sqlite3 mdr flatconf) \
	   -Wl,-z,relro -Wl,-z,now
ifneq ($(OVERRIDE_MDR),)
CFLAGS += -I$(OVERRIDE_MDR)
LDFLAGS += -L$(OVERRIDE_MDR) -Wl,-rpath,$(OVERRIDE_MDR)
endif

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

# PREFIX is the install prefix; DESTDIR is the staging root prepended to every
# path (empty for a real install, debian/tmp for the package build).
PREFIX ?= /usr/local
DESTDIR ?=
SBINDIR = $(PREFIX)/sbin
DATADIR = $(PREFIX)/share/certes
MANDIR = $(PREFIX)/share/man
DOCDIR = $(PREFIX)/share/doc/certes

SRCS = certes.c util.c certdb.c mdr_certes.c authority.c cert.c agent.c
OBJS = $(SRCS:.c=.o)

all: certes

certes: $(OBJS)
	$(CC) $(CFLAGS) -o certes $(OBJS) $(LDFLAGS)

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean
clean:
	rm -f certes *.o certes.core core

install: certes
	mkdir -p ${DESTDIR}${SBINDIR}
	mkdir -p ${DESTDIR}${DATADIR}
	mkdir -p ${DESTDIR}${DOCDIR}/examples
	mkdir -p ${DESTDIR}${MANDIR}/man5
	mkdir -p ${DESTDIR}${MANDIR}/man8

	install -m 0755 certes ${DESTDIR}${SBINDIR}/certes
	install -m 0644 openssl.cnf ${DESTDIR}${DATADIR}
	install -m 0755 setup_ca.sh ${DESTDIR}${DATADIR}
	install -m 0644 README ${DESTDIR}${DOCDIR}
	install -m 0644 LICENSE ${DESTDIR}${DOCDIR}
	install -m 0644 certes.conf.sample \
		${DESTDIR}${DOCDIR}/examples
	install -m 0644 certes_authority.conf.sample \
		${DESTDIR}${DOCDIR}/examples
	install -m 0644 *.5 ${DESTDIR}${MANDIR}/man5/
	install -m 0644 *.8 ${DESTDIR}${MANDIR}/man8/

-include $(DEPDIR)/*
