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
int arg_fuzz__argparse(const char *data, size_t data_len, int *argc, char **newargv);

#include <stdint.h>
#include <stddef.h>

// Should not be of any use
// int LLVMFuzzerInitialize(int *argc, char ***argv) {
//     ReadAndMaybeModify(argc, argv);
//     return 0;
// }

// In order to run this with LD_PRELOAD, compile it as:
// clang -g -fsanitize=fuzzer-no-link,address -shared -fPIC \
 -o argfuzz_libfuzzer.so ./argfuzz_libfuzzer.c \
 ~/path/to/libclang_rt.fuzzer_no_main-x86_64.a \
 -lstdc++ // Needs lib stdenv to work. Also see:\
 https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library  

// Also compile PUT (two args in this case) as:\
 clang -g -fsanitize=fuzzer-no-link,address ./examples/libfuzzer/two_args_libfuzzer.c 

extern int LLVMFuzzerRunDriver(int *argc, char ***argv,\
            int (*UserCb)(const uint8_t *Data, size_t Size));

extern int arg_fuzz__real_main(int, char **);
int (*arg_fuzz__main_ptr)(int, char **, char **);

int mut_argc;
char **mut_argv;
char ***senvp;

int LLVMFuzzerTestOneInpu(const uint8_t *Data, size_t Size) {
    // int mut_argc;
    // char **mut_argv;
    // Can we fork after malloc?
    // try(!(mut_argv = malloc(MAX_ARGC*sizeof(char*))), "Failed to allocate mut_argv\n");
    // int i;
    // for (i = 0; i < MAX_ARGC; i++){
    //     try(!(mut_argv[i] = malloc(MAX_ARG_LEN*sizeof(char))), "Failed to allocate mut_argv[i]\n");
    // }
    arg_fuzz__argparse((char *)Data, Size, &mut_argc, mut_argv);
    arg_fuzz__main_ptr(mut_argc, mut_argv, *senvp);
    // arg_fuzz__real_main(mut_argc, mut_argv); // What about envp?
    // for (i = 0; i < mut_argc; i++){
    //     free(mut_argv[i]);
    // }
    // free(mut_argv);
    return 0;
}

int arg_fuzz__argparse(const char *data, size_t data_len, int *argc, char **newargv){
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
    for (j = i+1; j < MAX_ARGC; j++){
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

// int (*arg_fuzz__main_ptr)(int, char **, char **);


int arg_fuzz__pre_main(int argc, char *argv[], char *envp[]){
    // int mut_argc;
    // char **mut_argv;
    printf("In premain\n");
    try(!(mut_argv = malloc(MAX_ARGC*sizeof(char*))), "Failed to allocate mut_argv\n");
    int i;
    for (i = 0; i < MAX_ARGC; i++){
        try(!(mut_argv[i] = malloc(MAX_ARG_LEN*sizeof(char))), "Failed to allocate mut_argv[i]\n");
    }
    senvp = &envp;

    LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInpu);

    for (i = 0; i < MAX_ARGC; i++){
        free(mut_argv[i]);
    }
    free(mut_argv);

        // arg_fuzz__argparse(buf, len, &mut_argc, mut_argv);
        // arg_fuzz__main_ptr(mut_argc, mut_argv, envp);

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
    printf("In libc\n");
    // save main function and call our custom main override
    arg_fuzz__main_ptr = func_ptr;
    return libc_start_main_orig(arg_fuzz__pre_main, argc, argv, init, fini, rtld_fini, stack_end);
}