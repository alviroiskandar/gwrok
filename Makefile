
CC ?= cc
CLFAGS ?= -Wall -Wextra -g -I/usr/include -I/usr/local/include -L/usr/lib -L/usr/local/lib -O2

all: gwrok

gwrok: gwrok.c
	$(CC) $(CLFAGS) -o gwrok gwrok.c -lpthread

clean:
	rm -f gwrok

.PHONY: all clean
