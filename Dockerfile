FROM aflplusplus/aflplusplus:latest as builder

# RUN apt update && sudo apt install -fy

COPY . /arg-fuzz

WORKDIR /arg-fuzz

# RUN ./bootstrap && ./configure CC=afl-gcc && make && make install

RUN mkdir /input

RUN echo seed > /input/seed

RUN make all

CMD ["make", "test"]
# CMD ["AFL_SKIP_CPUFREQ=1", "QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so", "AFL_BENCH_UNTIL_CRASH=1", "afl-fuzz", "-i", "/input", "-f", "seed", "-o", "/output", "-V", "60", "-G", "12", "-Q". "--", "/examples/one_arg"]

LABEL org.opencontainers.image.source=https://github.com/anastasist/arg-fuzz