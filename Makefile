CC := cc
CFLAGS := -Wall -g

all: certainty

certainty: certainty.c
	$(CC) $(CFLAGS) certainty.c -o certainty
