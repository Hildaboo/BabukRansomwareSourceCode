#include "args.h"

bool argz_option(int argc, wchar_t* argv[], const wchar_t* option) {
    /*
    option(argc, argv, option);
    Checks if a given option is active in the arguments.
    */
    wchar_t* arg;
    for (int i = 1; i < argc; i++) { /* Iterate over all arguments */
        arg = argv[i];
        if (*arg == L'-') { /* Options begin with a dash, anything else is an argument */
            while (*arg == L'-') { /* Skip past the dashes */
                arg++;
            }
            while (*option) { /* Compare the current option with the given one */
                if (*option != *arg) {
                    break; /* Uh oh, no match */
                }
                option++;
                arg++;
            }
            return true; /* There was a match */
        }
    }
    return false;
}

wchar_t* argz_arg(int argc, wchar_t* argv[], int index) {
    /*
    arg(argc, argv, index);
    Gets the argument at the given index in argv.
    */
    wchar_t* arg;
    int opts = 0;
    for (int i = 1; i < argc; i++) { /* Iterate over all arguments */
        arg = argv[i];
        if (*arg != L'-') { /* Hooray, we found an argument that is not an option */
            if (i - opts - 1 == index) {
                return arg; /* Yay, a match */
            }
        } else { /* Uh oh, we found an option */
            opts++;
        }
    }
    return 0; /* Return null string if no match was found */
}

wchar_t* argz_value(int argc, wchar_t* argv[], const wchar_t* key) {
    /*
    value(argc, argv, key);
    Get the value of the given key option (--x=y).
    */
    wchar_t* arg;
    int miss;
    for (int i = 1; i < argc; i++) { /* Iterate over all arguments */
        arg = argv[i];
        miss = 0;
        if (*arg == L'-') { /* We only care about options */
            while (*arg == L'-') { /* Skip the starting dashes */
                arg++;
            }
            while (*arg != L'=') { /* Compare the key, but stop before the value */
                if (*arg != *key) {
                    miss++;
                }
                arg++;
                key++;
            }
            if (miss == 0) { /* No difference between given key and this key, return the value */
                arg++;
                return arg;
            }
        }
    }
    return 0; /* Return null if no match was found */
}
