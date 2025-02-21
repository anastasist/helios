# Makefile to automatically build all .c files in the examples directory
CFLAGS += --coverage -ftest-coverage


default: all

all: $(patsubst %.c,%,$(wildcard *.c))

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean: $(patsubst %.c,%,$(wildcard *.c))
	rm -f $^

.PHONY: all clean