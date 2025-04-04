// Simplest example of a program with a single argument
// that crashes when the argument passed is bug

#include <stdio.h>
#include <string.h>


int main(int argc, char ** argv) {
    if (argc != 2) {
        printf("Usage: %s <arg1>\n", argv[0]);
        return 1;
    }
    if (argv[1][0] && argv[1][0] == 'b') {
        if (argv[1][1] && argv[1][1] == 'u') {
            if (argv[1][2] && argv[1][2] == 'g') {
                printf("Crashing...\n");
                int * crash = NULL;
                *crash = 0;
            }
        }
    }
    return 0;
}