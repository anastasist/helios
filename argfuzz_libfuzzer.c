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
// int LLVMFuzzerRunDriver(int *argc, char ***argv,\
//             int (*UserCb)(const uint8_t *Data, size_t Size));

extern int arg_fuzz__real_main(int, char **);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int mut_argc;
    char **mut_argv;
    // Can we fork after malloc?
    try(!(mut_argv = malloc(MAX_ARGC*sizeof(char*))), "Failed to allocate mut_argv\n");
    int i;
    for (i = 0; i < MAX_ARGC; i++){
        try(!(mut_argv[i] = malloc(MAX_ARG_LEN*sizeof(char))), "Failed to allocate mut_argv[i]\n");
    }
    arg_fuzz__argparse((char *)Data, Size, &mut_argc, mut_argv);
    arg_fuzz__real_main(mut_argc, mut_argv); // What about envp?
    for (i = 0; i < mut_argc; i++){
        free(mut_argv[i]);
    }
    free(mut_argv);
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
    // May need to revisit this behaviour - don't free memory so
    // the delayed fork server can utilize it?
    for (j = i; j < MAX_ARGC; j++){
        free(newargv[j]); // Ask about contiguous memory allocation and this segment
        newargv[j] = NULL;
    }
    *argc = i;
    return 0;
}
