## Makefile to build shared library to use as an LD_PRELOAD
## when running targets.

ARGFUZZ=test
ARGFUZZ_FOLDER=argfuzz

all: $(ARGFUZZ).so examples

default: all

$(ARGFUZZ).so: $(ARGFUZZ).c
	$(CC) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(ARGFUZZ).so"

clean:
	rm -f $(ARGFUZZ).so
	$(MAKE) -C examples clean

examples:
	$(MAKE) -C examples

shell:
	 docker run -v $(shell pwd):/$(ARGFUZZ_FOLDER) -w /$(ARGFUZZ_FOLDER) -it aflplusplus/aflplusplus:latest bash

test:
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so afl-fuzz -i input/ -o output -Q -- ./examples/one_arg

.PHONY: clean examples shell