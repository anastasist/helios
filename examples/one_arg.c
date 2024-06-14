// Simplest example of a program with a single argument
// that crashes when the argument passed is --magic

#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv) {
    if (argc != 2) {
        printf("Usage: %s <arg1>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "bug") == 0) {
        printf("Crashing...\n");
        int * crash = NULL;
        *crash = 0;
    }
    return 0;
}