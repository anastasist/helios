// A CLI program that takes in two arguments and crashes when
// the arguments provided are "-do" "crash".

#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv) {
    // if (argc == 5) {
    //     int *crash = NULL;
    //     *crash = 0;
    //     return 1;
    // }
    if (argc != 3) {
        printf("Usage: %s <arg1> <arg2>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "-do") == 0 && strcmp(argv[2], "crash") == 0) {
        printf("Crashing...\n");
        int *crash = NULL;
        *crash = 0;
    }
    return 0;
}