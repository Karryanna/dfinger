LD=gcc
CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -O2

OBJECTS=server.o client.o conf.o dfinger.o utils.o

.PHONY: clean

all: dfinger

dfinger: $(OBJECTS)
	gcc $(LDFLAGS) -o dfinger $(OBJECTS) $(LDLIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $^

clean:
	rm *.o
