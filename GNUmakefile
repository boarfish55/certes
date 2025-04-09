CC := gcc
DEPDIR := .deps
CFLAGS := -Wall -g -fstack-protector-strong \
	$(shell pkg-config --cflags libbsd-overlay libbsd-ctor)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	   libcrypto libssl sqlite3) \
	   -Wl,-z,relro -Wl,-z,now
YACC := byacc

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = certalator.c flatconf.c xlog.c util.c mdr.c mdr_mdrd.c certdb.c
OBJS = $(SRCS:.c=.o)

all: certalator

certalator: $(OBJS)
	$(CC) $(CFLAGS) -o certalator $(OBJS) $(LDFLAGS)

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean
clean:
	rm -f certalator *.o certalator.core core flatconf.c

-include $(DEPDIR)/*
