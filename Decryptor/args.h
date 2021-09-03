#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>
#include <stdio.h>

bool argz_option(int argc, wchar_t* argv[], const wchar_t* option);
wchar_t* argz_arg(int argc, wchar_t* argv[], int index);
wchar_t* argz_value(int argc, wchar_t* argv[], const wchar_t* key);

#endif
