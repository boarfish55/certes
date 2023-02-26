CC := cc
CFLAGS := -Wall -g

all: certainty

certainty: certainty.c
	$(CC) $(CFLAGS) certainty.c -lcrypto -lssl -ltls -o certainty

clean:
	rm -f certainty *.o
