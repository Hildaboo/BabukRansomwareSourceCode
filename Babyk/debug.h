#ifndef __H_DEBUG_
#define __H_DEBUG_

#include <windows.h>

void _dbg_report(LPCSTR message, LPCSTR target, DWORD error);
void _dbg_initialize(WCHAR* logFile);
void _dbg_uninitialize();

#endif