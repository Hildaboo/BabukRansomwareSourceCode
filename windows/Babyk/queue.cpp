#include <windows.h>

#include "memory.h"
#include "queue.h"

void _que_initialize(QUEUE* queue, INT size) {
    queue->queue_size = size;
    queue->buffer = (WCHAR**)_halloc(size * sizeof(WCHAR*));
    queue->space_avail = CreateSemaphoreA(NULL, size, size, NULL);
    queue->data_avail = CreateSemaphoreA(NULL, 0, size, NULL);
    queue->in_pos = 0;
    queue->out_pos = 0;
    InitializeCriticalSection(&(queue->mutex));
}

int _que_push(QUEUE* queue, LPWSTR data, int wait) {
    if (WaitForSingleObject(queue->space_avail, 0) != WAIT_OBJECT_0) {
        if (wait) WaitForSingleObject(queue->space_avail, INFINITE);
        else return 0;
    }

    EnterCriticalSection(&(queue->mutex));
    WCHAR* realloced_str = 0;
    if (data)
    {
        int memSize = sizeof(WCHAR) * (lstrlenW(data) + 1);
        realloced_str = (WCHAR*)_halloc(memSize);
        _memcpy(realloced_str, data, memSize);
    }
    queue->buffer[queue->in_pos] = realloced_str;
    queue->in_pos = (queue->in_pos + 1) % queue->queue_size;
    LeaveCriticalSection(&queue->mutex);
    ReleaseSemaphore(queue->data_avail, 1, NULL);

    return 1;
}

LPWSTR _que_pop(QUEUE* queue, int wait, int* dwError) {
    *dwError = 0;

    if (WaitForSingleObject(queue->data_avail, 0) != WAIT_OBJECT_0) {
        if (wait) WaitForSingleObject(queue->data_avail, INFINITE);
        else {
            *dwError = QUEUE_ERR_TIMEOUT;
            return 0;
        }
    }

    EnterCriticalSection(&queue->mutex);
    LPWSTR retval = queue->buffer[queue->out_pos];
    queue->out_pos = (queue->out_pos + 1) % queue->queue_size;
    LeaveCriticalSection(&queue->mutex);
    ReleaseSemaphore(queue->space_avail, 1, NULL);
    return retval;
}