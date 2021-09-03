#ifndef __MEMORY_H
#define __MEMORY_H
#include <windows.h>

void _mem_initialize();
void _hfree(void* mem);
void* _halloc(SIZE_T count);
void _memset(void* mem, BYTE val, SIZE_T count);
void _memcpy(void* dst, const void* src, SIZE_T count);

#endif