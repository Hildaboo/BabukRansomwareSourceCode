#ifndef QUEUE_H_INCLUDED
#define QUEUE_H_INCLUDED

#define QUEUE_ERR_TIMEOUT -1

#include <windows.h>

struct QUEUE {
	HANDLE space_avail;
	HANDLE data_avail;
	CRITICAL_SECTION mutex;
	INT queue_size = 0;
	LPWSTR* buffer = 0;
	long in_pos = 0;
	long out_pos = 0;
};

void _que_initialize(QUEUE* queue, INT size);

LPWSTR _que_pop(QUEUE* queue, int wait, int* dwError);
int _que_push(QUEUE* queue, LPWSTR data, int wait);

#endif