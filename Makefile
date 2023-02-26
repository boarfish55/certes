CC := cc
CFLAGS := -Wall -g

all: certainty

certainty: certainty.c
	$(CC) $(CFLAGS) certainty.c -lssl -o certainty

clean:
	rm -f certainty *.o
