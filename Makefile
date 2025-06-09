## Makefile to build shared library to use as an LD_PRELOAD
## when running targets.

CC?=afl-clang-fast
HELIOS_AFL=helios_afl
HELIOS_LIBF=helios_libfuzzer
ARGFUZZ_FOLDER=argfuzz
TIME?=60

all: $(HELIOS_AFL).so $(HELIOS_LIBF).so examples

default: all

$(HELIOS_AFL).so: $(HELIOS_AFL).c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(HELIOS_AFL).so"

$(HELIOS_LIBF).so: $(HELIOS_LIBF).c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<
	@echo "Shared library created: $(HELIOS_LIBF).so"

clean:
	$(MAKE) -C examples/afl clean
	$(MAKE) -C examples/libfuzzer clean
	rm -f $(HELIOS_AFL).so $(HELIOS_LIBF).so

examples:
	$(MAKE) -C examples/afl
	$(MAKE) -C examples/libfuzzer

shell:
	 docker run -v $(shell pwd):/$(ARGFUZZ_FOLDER) -w /$(ARGFUZZ_FOLDER) -it aflplusplus/aflplusplus:latest bash

	# AFL_INST_LIBS=1 \

2argcmplog:
	AFL_INST_LIBS=1 \
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(HELIOS_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 12 \
	-c ./examples/afl/two_args-cmplog -- \
	./examples/afl/two_args-afl

	
	# AFL_INST_LIBS=1 \
	# QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(HELIOS_AFL).so \
	# -Q -- \
	#
	
test:
	python3 -c 'print("a\0bug\0")' > ./seed
	AFL_SKIP_CPUFREQ=1 \
	AFL_PRELOAD=$(shell pwd)/$(HELIOS_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-o output \
	-G 12 \
	./examples/afl/two_args
	
actions-test:
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(HELIOS_AFL).so \
	AFL_BENCH_UNTIL_CRASH=1 \
	afl-fuzz \
	-i input/ \
	-f seed \
	-o output \
	-G 12 \
	-V 60 \
	-Q -- \
	./examples/afl/one_arg

demo_one:
	AFL_SKIP_CPUFREQ=1 \
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(HELIOS_AFL).so \
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
	QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(HELIOS_AFL).so \
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