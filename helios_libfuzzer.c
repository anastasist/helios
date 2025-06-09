#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>


#define MAX_FUZZ_BUFFER_SIZE 1024000

// ARG_MAX is the maximum length of a command invocation.
// A single argument, being a string, has a minimum length
// of 2 (except the last one), so we keep an array of half
// the maximum length to account for all possible invocations.
// In afl++ mode, 1024000 (afl buffer length) will replace ARG_MAX
char *argv_max[1024000/2];
char fuzz_buf[MAX_FUZZ_BUFFER_SIZE];

int newargc;
char ***senvp;

// #ifndef MAX_ARGC
// #define MAX_ARGC 16
// #endif

// #ifndef MAX_ARG_LEN
// #define MAX_ARG_LEN 128000
// #endif

#ifndef ARG_MAX
    long ARG_MAX;
#endif

#define try(cond, error) do { if (cond) { perror(error); exit(1); }} while(0);

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

// extern int LLVMFuzzerRunDriver(int *argc, char ***argv,\
//             int (*UserCb)(const uint8_t *Data, size_t Size));

// // extern int _helios__real_main(int, char **);
// int (*_helios__main_ptr)(int, char **, char **);
// int _helios__argparse(char *data, size_t data_len, int *argc, char **newargv);

// int User_LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
//     _helios__argparse((char *)Data, Size, &newargc, argv_max);
//     _helios__main_ptr(newargc, argv_max, *senvp);
//     return 0;
// }

// extern void foo(void);

// Isomorphism converting a single byte array into an array of null-terminated strings.
int _helios__argparse(char *data, size_t data_len, int *argc, char **newargv){
    size_t data_i, argv_i;
    data_i = argv_i = 0;
    // fprintf(stderr, "Parsing %zu bytes of data into arguments...\n", data_len);
    // fflush(stderr);
    assert(data_len + 1 < MAX_FUZZ_BUFFER_SIZE);
    memcpy(fuzz_buf, data, data_len);
    fuzz_buf[data_len] = '\0'; // Ensure the last byte is null-terminated

    newargv[argv_i++] = (char *)fuzz_buf;
    while (data_i + 1 < data_len){
        // Case for non \0 char
        if (fuzz_buf[data_i++])
            continue;
        newargv[argv_i++] = (char *)(&(fuzz_buf[data_i]));
    }
    fuzz_buf[data_i] = '\0'; // Ensure the last argument is null-terminated
    newargv[argv_i] = NULL;
    *argc = argv_i;
    return 0;
}

extern int helios__main(int, char **);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Parse the input data into arguments
    _helios__argparse((char *)Data, Size, &newargc, argv_max);

    // print argc and all arguments in hex form
    // fprintf(stderr, "Parsed %d arguments:\n", newargc);
    // for (int i = 0; i < newargc; i++) {
    //     fprintf(stderr, "argv[%d]: ", i);
    //     for (char *p = argv_max[i]; *p; p++) {
    //         fprintf(stderr, "%02x ", (unsigned char)*p);
    //     }
    //     fprintf(stderr, "\n");
    // }
    // fflush(stderr);

    // Call the main function with the parsed arguments
    // foo();
    // fprintf(stderr, "Calling main with %d arguments main at %p...\n", newargc, helios__main);
    // fprintf(stderr, "Contents of function pointer: %p\n", *helios__main);
    // fflush(stderr);
    int result = helios__main(newargc, argv_max);
    // fprintf(stderr, "Result of main: %d\n", result);
    // fflush(stderr);
    return result;
}


// int _helios__pre_main(int argc, char *argv[], char *envp[]){
//     senvp = &envp;

//     #ifndef ARG_MAX
//         try((ARG_MAX = sysconf(_SC_ARG_MAX)) == -1, "Failed to get ARG_MAX from system\n");
//     #endif

//     LLVMFuzzerRunDriver(&argc, &argv, User_LLVMFuzzerTestOneInput);

//         // arg_fuzz__argparse(buf, len, &mut_argc, mut_argv);
//         // arg_fuzz__main_ptr(mut_argc, mut_argv, envp);

//     return 0;
// }

// // Function pointer to the original libc_start_main function
// int (*libc_start_main_orig)(int (*main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end));

// int __libc_start_main(void * func_ptr, int argc, char * argv[], void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end)) {

//     // Get the original libc_start_main function
//     libc_start_main_orig = dlsym(RTLD_NEXT, "__libc_start_main");
//     if (libc_start_main_orig == NULL) {
//         fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
//         exit(1);
//     }

//     // save main function and call our custom main override
//     _helios__main_ptr = func_ptr;
//     return libc_start_main_orig(_helios__pre_main, argc, argv, init, fini, rtld_fini, stack_end);
// }