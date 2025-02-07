FROM aflplusplus/aflplusplus:latest as builder

# RUN apt update && sudo apt install -fy

COPY . /arg-fuzz

WORKDIR /arg-fuzz

# RUN ./bootstrap && ./configure CC=afl-gcc && make && make install

RUN mkdir -p input

# Docker directory creations require root priviledges :)
RUN mkdir -p output/default/.synced
RUN mkdir -p output/default/crashes
RUN mkdir -p output/default/hangs
RUN mkdir -p output/default/queue/.state/auto_extras
RUN mkdir -p output/default/queue/.state/deterministic_done
RUN mkdir -p output/default/queue/.state/redundant_edges
RUN mkdir -p output/default/queue/.state/variable_behavior

RUN echo seed > input/seed

RUN make all

CMD ["make", "test"]
# CMD ["AFL_SKIP_CPUFREQ=1", "QEMU_SET_ENV=LD_PRELOAD=$(shell pwd)/$(ARGFUZZ).so", "AFL_BENCH_UNTIL_CRASH=1", "afl-fuzz", "-i", "/input", "-f", "seed", "-o", "/output", "-V", "60", "-G", "12", "-Q". "--", "/examples/one_arg"]

RUN cp -r output/* /output/

LABEL org.opencontainers.image.source=https://github.com/anastasist/arg-fuzz