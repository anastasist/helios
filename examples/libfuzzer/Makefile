# Makefile to automatically build all .c files in the examples directory
CC = clang
CFLAGS += -g -fsanitize=fuzzer-no-link


default: all

all: $(patsubst %.c,%,$(wildcard *.c))

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean: $(patsubst %.c,%,$(wildcard *.c))
	rm -f $^

.PHONY: all clean