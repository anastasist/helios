// A CLI program that takes in two arguments and crashes when
// the arguments provided are "-do" "crash".

#include <stdio.h>
#include <string.h>

int mystrcmp(const char *, const char *);

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
    if (mystrcmp(argv[1], "-do") == 0 && mystrcmp(argv[2], "crash") == 0) {
        printf("Crashing...\n");
        int *crash = NULL;
        *crash = 0;
    }
    return 0;
}

int mystrcmp(const char *str1, const char *str2){
    while (*str1++ == *str2++ && *(str1-1));
    return *(str1-1) - *(str2-1);
}
