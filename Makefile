## Makefile to build shared library to use as an LD_PRELOAD
## when running targets.

ARGFUZZ=test

all: $(ARGFUZZ).so examples

default: all

$(ARGFUZZ).so: $(ARGFUZZ).c
	$(CC) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(ARGFUZZ).so"

clean:
	rm -f $(ARGFUZZ).so
	@echo "Shared library removed: $(ARGFUZZ).so"

examples:
	$(MAKE) -C examples

.PHONY: clean examples