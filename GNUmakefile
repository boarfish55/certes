CC := gcc
VERSION = 0.5.6
DEPDIR := .deps
CFLAGS := -Wall -g -fstack-protector-strong -DOPENSSL_API_COMPAT=0x10101000L \
	  -fstack-clash-protection -fcf-protection \
	  $(shell pkg-config --cflags libbsd-overlay libbsd-ctor mdr flatconf)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	   libcrypto libssl sqlite3 mdr flatconf) \
	   -Wl,-z,relro -Wl,-z,now
ifneq ($(OVERRIDE_MDR),)
CFLAGS += -I$(OVERRIDE_MDR)
LDFLAGS += -L$(OVERRIDE_MDR) -Wl,-rpath,$(OVERRIDE_MDR)
endif

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d
DESTDIR ?= /usr/local

SRCS = certes.c util.c certdb.c mdr_certes.c authority.c cert.c agent.c
OBJS = $(SRCS:.c=.o)

all: certes

certes: $(OBJS)
	$(CC) $(CFLAGS) -o certes $(OBJS) $(LDFLAGS)

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean
clean:
	rm -f certes *.o certes.core core

install: certes
	mkdir -p ${DESTDIR}/sbin
	mkdir -p ${DESTDIR}/share/certes
	mkdir -p ${DESTDIR}/share/doc/certes/examples
	mkdir -p ${DESTDIR}/share/man/man5
	mkdir -p ${DESTDIR}/share/man/man8

	install -m 0755 -s certes ${DESTDIR}/sbin/certes
	install -m 0644 openssl.cnf ${DESTDIR}/share/certes
	install -m 0755 setup_ca.sh ${DESTDIR}/share/certes
	install -m 0644 README ${DESTDIR}/share/doc/certes
	install -m 0644 LICENSE ${DESTDIR}/share/doc/certes
	install -m 0644 certes.conf.sample \
		${DESTDIR}/share/doc/certes/examples
	install -m 0644 certes_authority.conf.sample \
		${DESTDIR}/share/doc/certes/examples
	install -m 0644 *.5 ${DESTDIR}/share/man/man5/
	install -m 0644 *.8 ${DESTDIR}/share/man/man8/

-include $(DEPDIR)/*
