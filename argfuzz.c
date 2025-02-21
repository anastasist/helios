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

#ifndef MAX_ARGC
#define MAX_ARGC 16
#endif

#ifndef MAX_ARG_LEN
#define MAX_ARG_LEN 128000
#endif


#define try(cond, error) do { if (cond) { perror(error); exit(1); }} while(0);

// char mutated_argv[MAX_ARGC][MAX_ARG_LEN];

#ifdef __ARGFUZZ_LIBFUZZER__
#include <stdint.h>
#include <stddef.h>

// Should not be of any use
// int LLVMFuzzerInitialize(int *argc, char ***argv) {
//     ReadAndMaybeModify(argc, argv);
//     return 0;
// }
// int LLVMFuzzerRunDriver(int *argc, char ***argv,\
//             int (*UserCb)(const uint8_t *Data, size_t Size));

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Make callee function a main wrapper that is defined in test source file
    // FuzzMe(Data, Size);
    __builtin_trap();
    return 0;
}

int main(int argc, char *argv[]){
    // Call argparse
    // Call LLVMFuzzerTestOneInput with real_main

}

#endif

int arg_fuzz__argparse(char *data, size_t data_len, int *argc, char **newargv){
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
    newargv[i][j] = '\0';
    // May need to revisit this behaviour - don't free memory so
    // the delayed fork server can utilize it?
    for (j = i; j < MAX_ARGC; j++){
        free(newargv[j]); // Ask about contiguous memory allocation and this segment
        newargv[j] = NULL;
    }
    *argc = i;
    return 0;
}

int (*arg_fuzz__main_ptr)(int, char **, char **);

int arg_fuzz__pre_main(int argc, char *argv[], char *envp[]){
    #ifdef __ARGFUZZ_AFL__
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    // Delayed deferred forkserver on AFL
    // This is probably not a good idea:
    // https://github.com/google/AFL/blob/master/llvm_mode/README.llvm : line 114
    // Also only works with afl-clang-fast
        __AFL_INIT();
    // printf("In deforkserver\n");
    #endif
    return arg_fuzz__main_ptr(argc, argv, envp);
    #endif

    #ifdef __ARGFUZZ_LIBFUZZER__
    // TBI - use a main wrapper inside of TestOneInput
    // return ...
    #endif
    return 1;
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
 
    // Print out the arguments passed to main
    printf("argc: %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
 
    char **mut_argv;
    try(!(mut_argv = malloc(MAX_ARGC*sizeof(char*))), "Failed to allocate mut_argv\n");
    int i;
    for (i = 0; i < MAX_ARGC; i++){
        try(!(mut_argv[i] = malloc(MAX_ARG_LEN*sizeof(char))), "Failed to allocate mut_argv[i]\n");
    }
    // Add error checking and add check for fuzzer for seamless compatibility
    char *argfuzz = NULL;
    size_t argfuzz_len = 0;
    #ifdef __ARGFUZZ_AFL__
    FILE *argfuzz_seed = fopen("./seed", "r");
    try(argfuzz_seed == NULL, "Failed to open seed file\n");
    // Maybe directly access the fuzzable buffer instead of seed file
    // #ifdef __AFL_HAVE_MANUAL_CONTROL
    //     __AFL_INIT();
    // #endif
    try(!fseek(argfuzz_seed, 0L, SEEK_END),"Failed to fseek\n");
    argfuzz_len = ftell(argfuzz_seed);
    rewind(argfuzz_seed);
    try(!(argfuzz = malloc(sizeof(char) * argfuzz_len)), "Failed to malloc\n");
    int c, i = 0;
    while ((c = fgetc(argfuzz_seed)) != EOF) argfuzz[i++] = c;
    // Do not close
    // try(!fclose(argfuzz_seed), "Failed to fclose\n");
    int mut_argc;
    arg_fuzz__argparse(argfuzz, argfuzz_len, &mut_argc, mut_argv);


    printf("argc: %d\n", mut_argc);
    for (int i = 0; i <= mut_argc; i++) {
        printf("argv[%d]: %s\n", i, mut_argv[i]);
    }
    #endif

    #ifdef __ARGFUZZ_LIBFUZZER__
    // TBI
    // Do everything in pre-main to escape libc overhead
    #endif

    // Call the original libc_start_main function
    arg_fuzz__main_ptr = func_ptr;
    return libc_start_main_orig(arg_fuzz__pre_main, mut_argc, mut_argv, init, fini, rtld_fini, stack_end);
}