## Makefile to build shared library to use as an LD_PRELOAD
## when running targets.

ARGFUZZ_AFL=argfuzz_afl
ARGFUZZ_LIBF=argfuzz_libfuzzer
ARGFUZZ_FOLDER=argfuzz
TIME?=60

all: $(ARGFUZZ_AFL).so $(ARGFUZZ_LIBF).so examples

default: all

$(ARGFUZZ_AFL).so: $(ARGFUZZ_AFL).c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(ARGFUZZ_AFL).so"

$(ARGFUZZ_LIBF).so: $(ARGFUZZ_LIBF).c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(ARGFUZZ_LIBF).so"

clean:
	$(MAKE) -C examples/afl clean
	$(MAKE) -C examples/libfuzzer clean
	rm -f $(ARGFUZZ_AFL).so $(ARGFUZZ_LIBF).so

examples:
	$(MAKE) -C examples/afl
	$(MAKE) -C examples/libfuzzer

shell:
	 docker run -v $(shell pwd):/$(ARGFUZZ_FOLDER) -w /$(ARGFUZZ_FOLDER) -it aflplusplus/aflplusplus:latest bash

	# AFL_INST_LIBS=1 \

2argcmplog:
	AFL_INST_LIBS=1 \
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 12 \
	-c ./examples/afl/two_args-cmplog -- \
	./examples/afl/two_args-afl

	
test:
	# AFL_INST_LIBS=1 \
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 12 -- \
	./examples/afl/two_args
	# -Q -- \
	
actions-test:
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ_AFL).so \
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
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 5 \
	-V $(TIME) \
	-T "DEMO #1" \
	-Q -- \
	./examples/afl/one_arg

demo_two:
	# AFL_QEMU_PERSISTENT_GPR=1 \
	AFL_INST_LIBS=1 \
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 10 \
	-V $(TIME) \
	-T "DEMO #2" \
	-Q -- \
	./examples/afl/two_args

.PHONY: clean examples shell