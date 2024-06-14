// Program to be used as an LD_PRELOAD library to intercept calls to
// libc_start_main. This program will modify the arguments passed
// to main, and then call the original main function.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>


#define MAX_ARGC 16
#define MAX_ARG_LEN 128000

// char mutated_argv[MAX_ARGC][MAX_ARG_LEN];

int arg_fuzz__argparse(FILE *argfuzz, int *argc, char **newargv){
    int c, i, j;
    i = j = 0;
    while (i < MAX_ARGC-1){
        c = fgetc(argfuzz);
        if (c == EOF){
            newargv[i++][j] = '\0';
            break;
        }
        if (!c){
            newargv[i++][j] = '\0';
            j = 0;
            continue;
        }
        newargv[i][j++] = c;
    }
    for (j = i; j < MAX_ARGC; j++){
        free(newargv[j]);
        newargv[j] = NULL;
    }
    *argc = i;
    return 0;
}

// int (*arg_fuzz__pre_main)(int, char **, char **) = &arg_fuzz__init_deferred_forkserver
int (*arg_fuzz__main_ptr)(int, char **, char **);

int arg_fuzz__init_deferred_forkserver(int argc, char *argv[], char *envp[]){
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif
    printf("In deforkserver\n");
    return arg_fuzz__main_ptr(argc, argv, envp);
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
    if (!(mut_argv= malloc(MAX_ARGC*sizeof(char*)))){
        perror("Failed to allocate mut_argv\n");
        exit(1);
    }
    int i;
    for (i = 0; i < MAX_ARGC; i++){
        if (!(mut_argv[i]= malloc(MAX_ARG_LEN*sizeof(char)))){
            perror("Failed to allocate mut_argv[i]\n");
            exit(1);
        }
    }
    // Error check
    FILE *argfuzz = fopen("./seed", "r");
    int mut_argc;
    arg_fuzz__argparse(argfuzz, &mut_argc, mut_argv);


    printf("argc: %d\n", mut_argc);
    for (int i = 0; i <= mut_argc; i++) {
        printf("argv[%d]: %s\n", i, mut_argv[i]);
    }


    // Call the original libc_start_main function
    arg_fuzz__main_ptr = func_ptr;
    return libc_start_main_orig(arg_fuzz__init_deferred_forkserver, mut_argc, mut_argv, init, fini, rtld_fini, stack_end);
}