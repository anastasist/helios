Initializing repo

TODO:
👑
- [x] CI/CD github action build & test on push # Ask about alternatives and 777
- [ ] libfuzzer compatibility
- [ ] fix on arg2 (use red-queen?)
- [ ] revisit AFL_INST_LIBS


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