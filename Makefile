## Makefile to build shared library to use as an LD_PRELOAD
## when running targets.

ARGFUZZ=test
ARGFUZZ_FOLDER=argfuzz
TIME?=60

all: $(ARGFUZZ).so examples

default: all

$(ARGFUZZ).so: $(ARGFUZZ).c
	$(CC) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(ARGFUZZ).so"

clean:
	rm -f $(ARGFUZZ).so
	$(MAKE) -C examples/afl clean

examples:
	$(MAKE) -C examples/afl

shell:
	 docker run -v $(shell pwd):/$(ARGFUZZ_FOLDER) -w /$(ARGFUZZ_FOLDER) -it aflplusplus/aflplusplus:latest bash

	# AFL_INST_LIBS=1 \
	
test:
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 12 \
	-Q -- \
	./examples/two_args
	
actions-test:
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 12 \
	-V 60 \
	-Q -- \
	./examples/one_arg

demo_one:
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 5 \
	-V $(TIME) \
	-T "DEMO #1" \
	-Q -- \
	./examples/one_arg

demo_two:
	# AFL_QEMU_PERSISTENT_GPR=1 \
	AFL_INST_LIBS=1 \
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 10 \
	-V $(TIME) \
	-T "DEMO #2" \
	-Q -- \
	./examples/two_args

.PHONY: clean examples shell