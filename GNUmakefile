CC := gcc
DEPDIR := .deps
CFLAGS := -Wall -g -fstack-protector-strong \
	$(shell pkg-config --cflags libbsd-overlay libbsd-ctor)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	   libcrypto libssl) \
	   -Wl,-z,relro -Wl,-z,now
YACC := byacc

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = certainty.c flatconf.c xlog.c util.c mdr.c mdr_mdrd.c
OBJS = $(SRCS:.c=.o)

all: certainty

certainty: $(OBJS)
	$(CC) $(CFLAGS) -o certainty $(OBJS) $(LDFLAGS)

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean
clean:
	rm -f certainty *.o certainty.core core flatconf.c

-include $(DEPDIR)/*
