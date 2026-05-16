/*
 * tb_win_min_launch.c  –  Launcher that starts Thunderbird (or any program)
 *                         with DLL injection to force-minimise all windows
 *                         created within a configurable time window.
 *
 * Usage:
 *   tb_win_min_launch.exe [--timeout <seconds>] [path_to_exe] [args...]
 *
 * Build (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -municode \
 *       -o tb_win_min_launch.exe tb_win_min_launch.c -lkernel32 -luser32
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shared.h"

#define DEFAULT_TIMEOUT_SEC 5

/* Common Thunderbird installation paths */
static const WCHAR *g_search_paths[] = {
    L"C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe",
    L"C:\\Program Files (x86)\\Mozilla Thunderbird\\thunderbird.exe",
    NULL
};

static const WCHAR *find_thunderbird(void) {
    for (int i = 0; g_search_paths[i]; i++) {
        DWORD attr = GetFileAttributesW(g_search_paths[i]);
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
            return g_search_paths[i];
    }
    return NULL;
}

static int get_dll_path(WCHAR *out, DWORD maxlen) {
    DWORD n = GetModuleFileNameW(NULL, out, maxlen);
    if (n == 0 || n >= maxlen) return 0;
    WCHAR *slash = wcsrchr(out, L'\\');
    if (!slash) slash = wcsrchr(out, L'/');
    if (slash) slash[1] = L'\0';
    else out[0] = L'\0';
    if (wcslen(out) + wcslen(L"tb_win_min_hook.dll") >= maxlen) return 0;
    wcscat(out, L"tb_win_min_hook.dll");
    return 1;
}

static int inject_dll(HANDLE hProcess, const WCHAR *dll_path) {
    size_t len = (wcslen(dll_path) + 1) * sizeof(WCHAR);
    void *remote = VirtualAllocEx(hProcess, NULL, len,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        fwprintf(stderr, L"VirtualAllocEx failed: %lu\n", GetLastError());
        return 0;
    }
    if (!WriteProcessMemory(hProcess, remote, dll_path, len, NULL)) {
        fwprintf(stderr, L"WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(hK32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, remote, 0, NULL);
    if (!hThread) {
        fwprintf(stderr, L"CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return 1;
}

int wmain(int argc, WCHAR *argv[]) {
    int timeout_sec = DEFAULT_TIMEOUT_SEC;
    const WCHAR *target_exe = NULL;

    /* Collect all non-option arguments starting from first non-option */
    int first_extra_idx = -1;

    /* Parse arguments */
    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--timeout") == 0 && i + 1 < argc) {
            timeout_sec = _wtoi(argv[i + 1]);
            if (timeout_sec <= 0) timeout_sec = DEFAULT_TIMEOUT_SEC;
            i += 2;
        } else if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            wprintf(L"Usage: tb_win_min_launch.exe [--timeout <sec>] [exe_path] [args...]\n");
            wprintf(L"  --timeout <sec>  Hook duration in seconds (default: %d)\n",
                    DEFAULT_TIMEOUT_SEC);
            wprintf(L"  exe_path         Path to executable (default: auto-detect Thunderbird)\n");
            return 0;
        } else if (wcscmp(argv[i], L"--") == 0) {
            /* Everything after -- is passed through */
            i++;
            if (i < argc && !target_exe) {
                target_exe = argv[i];
                i++;
            }
            if (first_extra_idx < 0 && i < argc) first_extra_idx = i;
            break;
        } else {
            if (!target_exe) {
                target_exe = argv[i];
            } else {
                if (first_extra_idx < 0) first_extra_idx = i;
            }
            i++;
        }
    }

    /* Find target executable */
    if (!target_exe) {
        target_exe = find_thunderbird();
        if (!target_exe) {
            fwprintf(stderr, L"Error: Cannot find Thunderbird. Specify the path.\n");
            return 1;
        }
        wprintf(L"Found Thunderbird: %ls\n", target_exe);
    }

    /* Get DLL path */
    WCHAR dll_path[MAX_PATH];
    if (!get_dll_path(dll_path, MAX_PATH)) {
        fwprintf(stderr, L"Error: Cannot determine DLL path.\n");
        return 1;
    }
    if (GetFileAttributesW(dll_path) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"Error: Hook DLL not found: %ls\n", dll_path);
        return 1;
    }

    wprintf(L"Target: %ls\n", target_exe);
    wprintf(L"DLL:    %ls\n", dll_path);
    wprintf(L"Timeout: %d seconds\n", timeout_sec);

    /* ── Create shared memory ─────────────────────────────────────────── */

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_READWRITE, 0, sizeof(TbSharedData),
                                     TB_SHARED_MEM_NAME);
    if (!hMap) {
        fwprintf(stderr, L"Error: CreateFileMapping failed: %lu\n", GetLastError());
        return 1;
    }
    TbSharedData *shared = (TbSharedData *)MapViewOfFile(
        hMap, FILE_MAP_WRITE, 0, 0, sizeof(TbSharedData));
    if (!shared) {
        fwprintf(stderr, L"Error: MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hMap);
        return 1;
    }
    shared->deadline_tick = GetTickCount64() + (ULONGLONG)timeout_sec * 1000;
    wcscpy(shared->dll_path, dll_path);

    /* ── Create ready event (DLL signals when hooks are installed) ───── */

    HANDLE hReady = CreateEventW(NULL, TRUE, FALSE, TB_READY_EVENT_NAME);

    /* ── Build command line ───────────────────────────────────────────── */

    /* Calculate required length */
    size_t cmdlen = wcslen(target_exe) + 3; /* quotes + space */
    if (first_extra_idx > 0) {
        for (int j = first_extra_idx; j < argc; j++)
            cmdlen += wcslen(argv[j]) + 3; /* quotes + space */
    }
    cmdlen += 1; /* null terminator */

    WCHAR *cmdline = (WCHAR *)malloc(cmdlen * sizeof(WCHAR));
    if (!cmdline) {
        fwprintf(stderr, L"Error: out of memory\n");
        return 1;
    }

    /* Always quote the executable path */
    swprintf(cmdline, cmdlen, L"\"%ls\"", target_exe);
    if (first_extra_idx > 0) {
        for (int j = first_extra_idx; j < argc; j++) {
            wcscat(cmdline, L" ");
            if (wcschr(argv[j], L' ') || wcschr(argv[j], L'\t')) {
                wcscat(cmdline, L"\"");
                wcscat(cmdline, argv[j]);
                wcscat(cmdline, L"\"");
            } else {
                wcscat(cmdline, argv[j]);
            }
        }
    }

    /* ── Create process suspended ─────────────────────────────────────── */

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWMINNOACTIVE;

    PROCESS_INFORMATION pi = {0};

    wprintf(L"Starting: %ls\n", cmdline);

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"Error: CreateProcess failed: %lu\n", GetLastError());
        free(cmdline);
        UnmapViewOfFile(shared);
        CloseHandle(hMap);
        if (hReady) CloseHandle(hReady);
        return 1;
    }
    free(cmdline);

    wprintf(L"Process created (PID %lu), injecting DLL...\n", pi.dwProcessId);

    /* ── Inject DLL ──────────────────────────────────────────────────── */

    if (!inject_dll(pi.hProcess, dll_path)) {
        fwprintf(stderr, L"Warning: DLL injection failed, resuming without hooks.\n");
    } else {
        wprintf(L"DLL injected.\n");

        /* Wait for the DLL to signal that hooks are installed (up to 3s) */
        if (hReady) {
            DWORD wr = WaitForSingleObject(hReady, 3000);
            if (wr == WAIT_OBJECT_0)
                wprintf(L"Hooks installed in target process.\n");
            else
                wprintf(L"Warning: hook ready signal timed out, proceeding.\n");
        }
    }

    /* Resume the main thread */
    ResumeThread(pi.hThread);
    wprintf(L"Process resumed. Hooks active for %d seconds.\n", timeout_sec);

    /* Keep shared memory alive until timeout expires */
    Sleep((DWORD)timeout_sec * 1000);

    wprintf(L"Timeout reached, exiting.\n");

    /* Cleanup */
    UnmapViewOfFile(shared);
    CloseHandle(hMap);
    if (hReady) CloseHandle(hReady);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
