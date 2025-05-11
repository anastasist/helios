// Program to be used as an LD_PRELOAD library to intercept calls to
// libc_start_main. This program will modify the arguments passed
// to main, and then call the original main function.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

// ARG_MAX is the maximum length of a command invocation.
// A single argument, being a string, has a minimum length
// of 2 (except the last one), so we keep an array of half 
// the maximum length to account for all possible invocations.
// In afl++ mode, 1024000 (afl buffer length) will replace ARG_MAX
char *argv_max[1024000/2];

// #ifndef MAX_ARGC
// #define MAX_ARGC 16
// #endif

// #ifndef MAX_ARG_LEN
// #define MAX_ARG_LEN 128000
// #endif


#define try(cond, error) do { if (cond) { fprintf(stderr, "%s\n", strerror(errno)); perror(error); exit(1); }} while(0);

#ifndef __AFL_FUZZ_TESTCASE_LEN
    ssize_t fuzz_len;
    #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
    unsigned char fuzz_buf[1024000];
    #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
    #define __AFL_FUZZ_INIT() void sync(void);
    #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
    #define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT();

#pragma clang optimize off
#pragma gcc optimize("O0")

int _helios__argparse(unsigned char *data, ssize_t data_len, int *argc, char **newargv){
    unsigned int data_i, argv_i;
    data_i = argv_i = 0;

    newargv[argv_i++] = (char *)data;
    while (data_i < data_len - 1){
        // Case for non \0 char
        if (data[data_i++])
            continue;
        newargv[argv_i++] = (char *)(&(data[data_i]));
    }
    data[data_i] = '\0';
    newargv[argv_i] = NULL;
    *argc = argv_i;
    return 0;
}

int (*_helios__main_ptr)(int, char **, char **);


int _helios__pre_main(int argc, char *argv[], char *envp[]){
    // Print out the arguments passed to main
    // printf("argc: %d\n", argc);
    // for (int i = 0; i < argc; i++) {
    //     printf("argv[%d]: %s\n", i, argv[i]);
    // }

    #ifndef ARG_MAX
        long ARG_MAX;
        try((ARG_MAX = sysconf(_SC_ARG_MAX)) == -1, "Failed to get ARG_MAX from system\n");
    #endif
 
    ssize_t len;
    unsigned char *buf;
    // Only works with afl-clang-fast
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    buf = __AFL_FUZZ_TESTCASE_BUF;

    while(__AFL_LOOP(10000)){    // Can change loop value depending on PUT stability
        len = __AFL_FUZZ_TESTCASE_LEN;
        
        // Zeroing newargv should not be needed since PUT should never
        // access argv array post argc index

        // Cutoff data that exceed ARG_MAX
        _helios__argparse(buf, len > ARG_MAX ? ARG_MAX : len, &argc, argv_max);
        _helios__main_ptr(argc, argv_max, envp);
    }
    
    return 0;
}

// Function pointer to the original libc_start_main function
int (*libc_start_main_orig)(int (*main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end));

int __libc_start_main(void * func_ptr, int argc, char * argv[], void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end)) {
 
    // Get the original libc_start_main function
    libc_start_main_orig = dlsym(RTLD_NEXT, "__libc_start_main");
    if (libc_start_main_orig == NULL) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(1);
    }
 
    // save main function and call our custom main override
    _helios__main_ptr = func_ptr;
    return libc_start_main_orig(_helios__pre_main, argc, argv, init, fini, rtld_fini, stack_end);
}
