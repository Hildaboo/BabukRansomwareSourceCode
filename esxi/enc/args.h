#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>
#include <stdio.h>

bool argz_option(int argc, char* argv[], char* option);
char* argz_arg(int argc, char* argv[], int index);

#endif
