#include "memory.h"

static HANDLE procHeap = 0;

void _hfree(void* mem) {
	HeapFree(procHeap, 0, mem);
}

void _memset(void* dst, BYTE val, SIZE_T count) {
	for (volatile int i = 0; i < count; i++) {
		((BYTE*)dst)[i] = val;
	}
}

void _memcpy(void* dst, const void* src, SIZE_T count) {
	for (volatile int i = 0; i < count; i++) {
		((BYTE*)dst)[i] = ((BYTE*)src)[i];
	}
}

void _mem_initialize() {
	procHeap = GetProcessHeap();
}

void* _halloc(SIZE_T count) {
retry:;
	LPVOID ret = HeapAlloc(procHeap, HEAP_ZERO_MEMORY, count + 64);
	if (!ret) goto retry;
	return ret;
}