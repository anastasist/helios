# Makefile to automatically build all .c files in the examples directory
CC=afl-gcc-fast # two_args crashes with afl-clang-fast ???
CFLAGS += --coverage -ftest-coverage
# LDFLAGS += -static-libgcc


default: all

all: $(patsubst %.c,%,$(wildcard *.c))

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean: $(patsubst %.c,%,$(wildcard *.c))
	rm -f $^

.PHONY: all clean