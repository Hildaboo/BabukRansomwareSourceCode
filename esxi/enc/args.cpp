#include "args.h"

bool argz_option(int argc, char* argv[], char* option) {
    char* arg;
    for (int i = 1; i < argc; i++) { /* Iterate over all arguments */
        arg = argv[i];
        if (*arg == '-') {
            while (*arg == '-') {
                arg++;
            }
            while (*option) {
                if (*option != *arg) {
                    return false;
                }
                option++;
                arg++;
            }
            return true;
        }
    }
    return false;
}

char* argz_arg(int argc, char* argv[], int index) {
    char* arg;
    int opts = 0;
    for (int i = 1; i < argc; i++) {
        arg = argv[i];
        if (*arg != '-') {
            if (i - opts - 1 == index) {
                return arg;
            }
        } else {
            opts++;
        }
    }
    return 0;
}
