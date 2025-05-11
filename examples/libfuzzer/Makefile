# Makefile to automatically build all .c files in the examples directory
CC = clang
CFLAGS += -g -fsanitize=fuzzer,address
LDFLAGS += ../../helios_libfuzzer.so
# LDFLAGS += -L../../argfuzz_libfuzzer.so -largfuzz_libfuzzer.so

default: all

all: $(patsubst %.c,%.argfuzz,$(wildcard *.c))

%.argfuzz.c: %.c
	../../convert.sh $<

%.argfuzz: %.argfuzz.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean: $(patsubst %.c,%.argfuzz,$(wildcard *.c))
	rm -f $^ *.argfuzz*

# %: %.c
# 	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# clean: $(patsubst %.c,%,$(wildcard *.c))
# 	rm -f $^

.PHONY: all clean