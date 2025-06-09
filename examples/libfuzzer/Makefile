# Makefile to automatically build all .c files in the examples directory
CC = clang
CFLAGS += -g -fsanitize=fuzzer,address -Dmain=helios__main ../../helios_libfuzzer.c
# LDFLAGS += ../../helios_libfuzzer.so
# LDFLAGS += -L../../argfuzz_libfuzzer.so -largfuzz_libfuzzer.so

default: all

all: $(patsubst %.c,%,$(wildcard *.c))

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean: $(patsubst %.c,%,$(wildcard *.c))
	rm -f $^

# %: %.c
# 	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# clean: $(patsubst %.c,%,$(wildcard *.c))
# 	rm -f $^

.PHONY: all clean