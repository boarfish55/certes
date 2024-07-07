CC := gcc
DEPDIR := .deps
CFLAGS := -Wall -g -fstack-protector-strong \
	$(shell pkg-config --cflags libbsd-overlay libbsd-ctor)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	   libcrypto libssl) \
	   -Wl,-z,relro -Wl,-z,now

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

SRCS = certainty.c config_vars.c xlog.c util.c mdr.c
OBJS = $(SRCS:.c=.o)

all: certainty

certainty: $(OBJS)
	$(CC) $(CFLAGS) -o certainty $(OBJS) $(LDFLAGS)

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

.PHONY: clean
clean:
	rm -f certainty *.o certainty.core core

-include $(DEPDIR)/*
