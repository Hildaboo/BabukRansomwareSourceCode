#include "Memory.h"

static HANDLE proc_heap = 0;

void _hfree(void* mem) {
	HeapFree(proc_heap, 0, mem);
}

void _memset(void* dst, BYTE val, SIZE_T count) {
	for (volatile int i = 0; i < count; i++) {//volatile убирает оптимизацию с подставлением ебучих memcpy, memset
		((BYTE*)dst)[i] = val;
	}
}

void _memcpy(void* dst, const void* src, SIZE_T count) {
	for (volatile int i = 0; i < count; i++) {//volatile убирает оптимизацию с подставлением ебучих memcpy, memset
		((BYTE*)dst)[i] = ((BYTE*)src)[i];
	}
}

void _mem_initialize() {
	proc_heap = GetProcessHeap();
}

void* _halloc(SIZE_T count) {
retry:;
	LPVOID ret = HeapAlloc(proc_heap, HEAP_ZERO_MEMORY, count + 64);
	if (ret == 0) goto retry;
	return ret;
}