#include <windows.h>

#include "debug.h"

static HANDLE h_log_file = 0;
static CRITICAL_SECTION critSection;

void _dbg_initialize(WCHAR* logFile) {
	InitializeCriticalSection(&critSection);
	h_log_file = CreateFileW(logFile, GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
}

void _dbg_report(LPCSTR message, LPCSTR target, DWORD error) {
	CHAR err[20];
	DWORD dw;

	EnterCriticalSection(&critSection);
	wsprintfA(err, "%lu", error);
	WriteFile(h_log_file, message, lstrlenA(message), &dw, 0);
	WriteFile(h_log_file, ", Error Code: ", 14, &dw, 0);
	WriteFile(h_log_file, err, lstrlenA(err), &dw, 0);
	WriteFile(h_log_file, " -> ", 4, &dw, 0);
	WriteFile(h_log_file, target, lstrlenA(target), &dw, 0);
	WriteFile(h_log_file, "\r\n", 2, &dw, 0);
	LeaveCriticalSection(&critSection);
}

void _dbg_uninitialize() {
	DeleteCriticalSection(&critSection);
	CloseHandle(h_log_file);
}