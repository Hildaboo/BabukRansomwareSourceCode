#ifndef QUEUE_H_INCLUDED
#define QUEUE_H_INCLUDED

#include <windows.h>

void _que_initialize(INT size);
void _que_push(LPWSTR data);
LPWSTR _que_pop();

#endif