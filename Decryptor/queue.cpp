#include <windows.h>

#include "memory.h"
#include "queue.h"

static HANDLE space_avail;
static HANDLE data_avail;
static CRITICAL_SECTION mutex;

static INT queueSize = 0;

static LPWSTR* buffer = 0;
static long in_pos = 0, out_pos = 0;

void _que_initialize(INT size) {
    queueSize = size;
    buffer = (WCHAR**)_halloc(size * sizeof(WCHAR*));

    space_avail = CreateSemaphoreA(NULL, queueSize, queueSize, NULL);
    data_avail = CreateSemaphoreA(NULL, 0, queueSize, NULL);
    InitializeCriticalSection(&mutex);
}

void _que_push(LPWSTR data) {
    WCHAR* data_newmem = 0;
    if (data)
    {
        data_newmem = (WCHAR*)_halloc(sizeof(WCHAR*) * (lstrlenW(data) + 1));
        lstrcpyW(data_newmem, data);
    }

    WaitForSingleObject(space_avail, INFINITE);
    EnterCriticalSection(&mutex);
    buffer[in_pos] = data_newmem;
    in_pos = (in_pos + 1) % queueSize;
    LeaveCriticalSection(&mutex);
    ReleaseSemaphore(data_avail, 1, NULL);
}

LPWSTR _que_pop() {
    WaitForSingleObject(data_avail, INFINITE);
    EnterCriticalSection(&mutex);
    LPWSTR retval = buffer[out_pos];
    out_pos = (out_pos + 1) % queueSize;
    LeaveCriticalSection(&mutex);
    ReleaseSemaphore(space_avail, 1, NULL);
    return retval;
}