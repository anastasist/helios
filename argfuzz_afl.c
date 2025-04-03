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

#ifndef MAX_ARGC
#define MAX_ARGC 16
#endif

#ifndef MAX_ARG_LEN
#define MAX_ARG_LEN 128000
#endif


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

int arg_fuzz__argparse(const unsigned char *data, ssize_t data_len, int *argc, char **newargv){
    unsigned int data_i, i, j;
    char c;
    data_i = i = j = 0;
    while (data_i < data_len){
        c = data[data_i++];
        // Case for \0 char, which acts as argument separator
        if (!c){
            newargv[i++][j] = '\0';
            if (i == MAX_ARGC) break;
            j = 0;
            continue;
        }
        newargv[i][j++] = c;
    }
    if (i < MAX_ARGC)
        newargv[i][j] = '\0';
    *argc = i;
    for (j = i + 1; i < MAX_ARGC; i++){
        newargv[j][0] = '\0';
    }
    // May need to revisit this behaviour - don't free memory so
    // the delayed fork server can utilize it?
    // for (j = i; j < MAX_ARGC; j++){
    //     free(newargv[j]); // Ask about contiguous memory allocation and this segment
    //     newargv[j] = NULL;
    // }
    return 0;
}

int (*arg_fuzz__main_ptr)(int, char **, char **);


int arg_fuzz__pre_main(int argc, char *argv[], char *envp[]){
    // Print out the arguments passed to main
    printf("argc: %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
 
    int mut_argc;
    char **mut_argv;
    try(!(mut_argv = malloc(MAX_ARGC*sizeof(char*))), "Failed to allocate mut_argv\n");
    int i;
    for (i = 0; i < MAX_ARGC; i++){
        try(!(mut_argv[i] = malloc(MAX_ARG_LEN*sizeof(char))), "Failed to allocate mut_argv[i]\n");
    }
    // Add error checking and add check for fuzzer for seamless compatibility

    ssize_t len;
    unsigned char *buf;
    // Delayed deferred forkserver on AFL
    // This is probably not a good idea:
    // https://github.com/google/AFL/blob/master/llvm_mode/README.llvm : line 114
    // Also only works with afl-clang-fast
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        // __AFL_INIT();
    printf("In deforkserver\n");
    #endif

    buf = __AFL_FUZZ_TESTCASE_BUF;

    while(__AFL_LOOP(1000)){    // Can change loop value depending on PUT stability
        len = __AFL_FUZZ_TESTCASE_LEN;

        arg_fuzz__argparse(buf, len, &mut_argc, mut_argv);
        arg_fuzz__main_ptr(mut_argc, mut_argv, envp);
    }

    for (i = 0; i < MAX_ARGC; i++){
        free(mut_argv[i]);
    }
    free(mut_argv);
    
    // Maybe directly access the fuzzable buffer instead of seed file
    // char *argfuzz = NULL;
    // ssize_t argfuzz_len = 0;
    // FILE *argfuzz_seed = fopen("./seed", "r");
    // try(argfuzz_seed == NULL, "Failed to open seed file\n");
    // try(fseek(argfuzz_seed, 0L, SEEK_END),"Failed to fseek\n");
    // argfuzz_len = ftell(argfuzz_seed) + 1;
    // rewind(argfuzz_seed);
    // try(!(argfuzz = malloc(sizeof(char) * (argfuzz_len))), "Failed to malloc\n");
    // int c;
    // i = 0;
    // while ((c = fgetc(argfuzz_seed)) != EOF) argfuzz[i++] = c;
    // argfuzz[i] = '\0';
    // Do not close
    // try(fclose(argfuzz_seed), "Failed to fclose\n");


    // Direct buffer access in loop:
    // printf("argfuzz: %s\n", argfuzz);
    // arg_fuzz__argparse(argfuzz, argfuzz_len, &mut_argc, mut_argv);
    // arg_fuzz__main_ptr(mut_argc, mut_argv, envp);
    // free(argfuzz);


    // printf("mutargc: %d\n", mut_argc);
    // for (int i = 0; i <= mut_argc; i++) {
    //     printf("mutargv[%d]: %s\n", i, mut_argv[i]);
    // }

    // Call the original main function

    // return arg_fuzz__main_ptr(mut_argc, mut_argv, envp);
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
    arg_fuzz__main_ptr = func_ptr;
    return libc_start_main_orig(arg_fuzz__pre_main, argc, argv, init, fini, rtld_fini, stack_end);
}
