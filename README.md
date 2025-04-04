Initializing repo

TODO:
👑
- [x] CI/CD github action build & test on push # Ask about alternatives and 777
- [x] libfuzzer compatibility # Must clean test lib code, not hardcode
- [ ] fix AFL on arg2 (use red-queen?)
- [ ] revisit AFL_INST_LIBS
- [x] source modification + libfuzzer - argfuzz as linked lib - modify source with functions
- [ ] ldflags modification + libfuzzer
- [ ] ιδέα για το two_arg.c πρόβλημα
- [ ] ELF parser/transformation to inject new entrypoint
- [x] check __AFL_HAVE_MANUAL_CONTROL - might not work properly by default
- [ ] pytest
- [ ] dev branch to main
- [ ] make more tests
- [ ] update patched sudo in package
- [ ] sudo demo Friday
- [ ] make own strcmp to test afl


- [ ] refactor code - make project single header file
- [ ] sanitizers
- [x] delayed fork server
- [ ] blacklist address ranges
- [ ] getopt/optlong/arg_parse
- [ ] protobuf*
- [ ] help and strings dictionary
- [ ] ascii only
- [ ] cfuzz (on one_arg)
- [ ] https://github.com/CodeIntelligenceTesting/ci-fuzz-cli-tutorials
- [ ] gcof-lcov compilation flags
- [ ] checkpoint after libc argument parsing

Check:

    for coverage:
    - gcov (compile with `-ftest-coverage` and `--coverage` and invoke with -agk and maybe -Hbq)
    - lcov
    - QEMU
    - bncov
    - check other arg fuzzers and compare with that and symbolic execeutors like Klee


TODO until meeting:
- Name arg_fuzz to something cool
- make demos and test them with a configurable timeout
- show with a coverage measurement tool that takes in directory of test cases and emits coverage metrics (source based unless unable)
- Stretch: run opponent tool to compare
- Make github repo public and use github actions for testing changes (artifacts)