CC := gcc
DEPDIR := .deps
CFLAGS := -Wall -g -fstack-protector-strong -Wformat=0 \
	  -Wdeprecated-declarations -fstack-clash-protection \
	  -fcf-protection \
	  $(shell pkg-config --cflags libbsd-overlay libbsd-ctor mdr \
	  flatconf)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	   libcrypto libssl sqlite3 mdr flatconf) \
	   -Wl,-z,relro -Wl,-z,now
YACC := byacc

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = certalator.c util.c certdb.c mdr_certalator.c authority.c cert.c agent.c
OBJS = $(SRCS:.c=.o)

all: certalator

certalator: $(OBJS)
	$(CC) $(CFLAGS) -o certalator $(OBJS) $(LDFLAGS)

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean
clean:
	rm -f certalator *.o certalator.core core

-include $(DEPDIR)/*
