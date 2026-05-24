/*
 * tb_win_min_hook.c – Injected DLL that hooks ShowWindow, CreateProcessW/A
 * to minimise windows shown within a time window and propagate to children.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <string.h>
#include "shared.h"
#include "MinHook.h"

/* Force user32.dll as a load-time dependency */
volatile void *_force_user32_import = (void *)&ShowWindow;

static ULONGLONG g_deadline = 0;
static WCHAR     g_dll_path[MAX_PATH] = {0};

static int is_within_deadline(void) {
    return GetTickCount64() < g_deadline;
}

static int load_shared_data(void) {
    HANDLE hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, TB_SHARED_MEM_NAME);
    if (!hMap) return 0;
    TbSharedData *p = (TbSharedData *)MapViewOfFile(
        hMap, FILE_MAP_READ, 0, 0, sizeof(TbSharedData));
    if (!p) { CloseHandle(hMap); return 0; }
    g_deadline = p->deadline_tick;
    wcscpy(g_dll_path, p->dll_path);
    UnmapViewOfFile(p);
    CloseHandle(hMap);
    return 1;
}

/* ── DLL injection helper ─────────────────────────────────────────────── */

static int inject_dll_into(HANDLE hProcess) {
    size_t len = (wcslen(g_dll_path) + 1) * sizeof(WCHAR);
    void *remote = VirtualAllocEx(hProcess, NULL, len,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return 0;
    if (!WriteProcessMemory(hProcess, remote, g_dll_path, len, NULL)) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(hK32, "LoadLibraryW");
    HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, remote, 0, NULL);
    if (!hRemote) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }
    WaitForSingleObject(hRemote, 10000);
    CloseHandle(hRemote);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return 1;
}

/* ── Original function pointers ───────────────────────────────────────── */

typedef BOOL (WINAPI *pfnShowWindow)(HWND, int);
typedef BOOL (WINAPI *pfnCreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *pfnCreateProcessA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static pfnShowWindow       fpShowWindow       = NULL;
static pfnCreateProcessW   fpCreateProcessW   = NULL;
static pfnCreateProcessA   fpCreateProcessA   = NULL;

/* ── Hooked functions ─────────────────────────────────────────────────── */

static int is_app_window(HWND hWnd) {
    if (!hWnd) return 0;
    if (GetParent(hWnd) != NULL) return 0;
    LONG style = GetWindowLongW(hWnd, GWL_STYLE);
    if (!(style & WS_CAPTION)) return 0;
    if (!(style & (WS_SYSMENU | WS_THICKFRAME))) return 0;
    return 1;
}

static BOOL WINAPI Hooked_ShowWindow(HWND hWnd, int nCmdShow) {
    if (is_within_deadline() && is_app_window(hWnd)) {
        switch (nCmdShow) {
        case SW_SHOW:
        case SW_SHOWNORMAL:
        case SW_SHOWDEFAULT:
        case SW_SHOWNA:
        case SW_SHOWNOACTIVATE:
        case SW_RESTORE:
        case SW_SHOWMAXIMIZED:
            // nCmdShow = SW_SHOWMINNOACTIVE;
            nCmdShow = SW_SHOWMINIMIZED;
            break;
        }
    }
    return fpShowWindow(hWnd, nCmdShow);
}

static BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApp, LPWSTR lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCWSTR lpDir,
    LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    if (!is_within_deadline())
        return fpCreateProcessW(lpApp, lpCmd, lpPA, lpTA, bInherit,
                                dwFlags, lpEnv, lpDir, lpSI, lpPI);

    int was_suspended = (dwFlags & CREATE_SUSPENDED) != 0;
    dwFlags |= CREATE_SUSPENDED;

    STARTUPINFOW si_copy = {0};
    if (lpSI)
        memcpy(&si_copy, lpSI,
               lpSI->cb <= sizeof(si_copy) ? lpSI->cb : sizeof(si_copy));
    si_copy.cb = sizeof(si_copy);
    si_copy.dwFlags |= STARTF_USESHOWWINDOW;
    // si_copy.wShowWindow = SW_SHOWMINNOACTIVE;
    si_copy.wShowWindow = SW_SHOWMINIMIZED;

    PROCESS_INFORMATION pi_local = {0};
    BOOL ret = fpCreateProcessW(lpApp, lpCmd, lpPA, lpTA, bInherit,
                                dwFlags, lpEnv, lpDir, &si_copy,
                                lpPI ? lpPI : &pi_local);
    if (ret) {
        HANDLE hProc = lpPI ? lpPI->hProcess : pi_local.hProcess;
        HANDLE hThr  = lpPI ? lpPI->hThread  : pi_local.hThread;
        if (hProc) inject_dll_into(hProc);
        if (!was_suspended && hThr) ResumeThread(hThr);
        if (!lpPI) {
            CloseHandle(pi_local.hProcess);
            CloseHandle(pi_local.hThread);
        }
    }
    return ret;
}

static BOOL WINAPI Hooked_CreateProcessA(
    LPCSTR lpApp, LPSTR lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCSTR lpDir,
    LPSTARTUPINFOA lpSI, LPPROCESS_INFORMATION lpPI)
{
    if (!is_within_deadline())
        return fpCreateProcessA(lpApp, lpCmd, lpPA, lpTA, bInherit,
                                dwFlags, lpEnv, lpDir, lpSI, lpPI);

    int was_suspended = (dwFlags & CREATE_SUSPENDED) != 0;
    dwFlags |= CREATE_SUSPENDED;

    STARTUPINFOA si_copy = {0};
    if (lpSI)
        memcpy(&si_copy, lpSI,
               lpSI->cb <= sizeof(si_copy) ? lpSI->cb : sizeof(si_copy));
    si_copy.cb = sizeof(si_copy);
    si_copy.dwFlags |= STARTF_USESHOWWINDOW;
    // si_copy.wShowWindow = SW_SHOWMINNOACTIVE;
    si_copy.wShowWindow = SW_SHOWMINIMIZED;

    PROCESS_INFORMATION pi_local = {0};
    BOOL ret = fpCreateProcessA(lpApp, lpCmd, lpPA, lpTA, bInherit,
                                dwFlags, lpEnv, lpDir, &si_copy,
                                lpPI ? lpPI : &pi_local);
    if (ret) {
        HANDLE hProc = lpPI ? lpPI->hProcess : pi_local.hProcess;
        HANDLE hThr  = lpPI ? lpPI->hThread  : pi_local.hThread;
        if (hProc) inject_dll_into(hProc);
        if (!was_suspended && hThr) ResumeThread(hThr);
        if (!lpPI) {
            CloseHandle(pi_local.hProcess);
            CloseHandle(pi_local.hThread);
        }
    }
    return ret;
}

/* ── Hook installation ────────────────────────────────────────────────── */

static void install_all_hooks(void) {
    if (MH_Initialize() != MH_OK) return;

    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        LPVOID pSW = (LPVOID)GetProcAddress(hUser32, "ShowWindow");
        if (pSW && MH_CreateHook(pSW, (LPVOID)Hooked_ShowWindow, (LPVOID *)&fpShowWindow) == MH_OK)
            MH_QueueEnableHook(pSW);
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        LPVOID pCPW = (LPVOID)GetProcAddress(hK32, "CreateProcessW");
        LPVOID pCPA = (LPVOID)GetProcAddress(hK32, "CreateProcessA");
        if (pCPW && MH_CreateHook(pCPW, (LPVOID)Hooked_CreateProcessW, (LPVOID *)&fpCreateProcessW) == MH_OK)
            MH_QueueEnableHook(pCPW);
        if (pCPA && MH_CreateHook(pCPA, (LPVOID)Hooked_CreateProcessA, (LPVOID *)&fpCreateProcessA) == MH_OK)
            MH_QueueEnableHook(pCPA);
    }

    MH_ApplyQueued();
}

/* ── DLL entry point ──────────────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        if (!load_shared_data() || !is_within_deadline())
            return TRUE;
        install_all_hooks();
        {
            HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, TB_READY_EVENT_NAME);
            if (hEvent) { SetEvent(hEvent); CloseHandle(hEvent); }
        }
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
