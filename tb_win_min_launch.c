/*
 * tb_win_min_launch.c – Launcher that starts a program with DLL injection
 * to force-minimise all windows created within a configurable time window.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <fcntl.h>
#include "shared.h"

#define DEFAULT_TIMEOUT_SEC 5

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
    if (!remote) return 0;
    if (!WriteProcessMemory(hProcess, remote, dll_path, len, NULL)) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(hK32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, remote, CREATE_SUSPENDED, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }

    ResumeThread(hThread);
    WaitForSingleObject(hThread, 15000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return 1;
}

// the following (and the calling part below) is copied and modified
// (so redirected outputs took into account) from contour-terminal/contour
// Copyright Contour authors, Apache License 2.0
static BOOL is_a_console(HANDLE h)
{
    DWORD modeDummy = 0;
    return GetConsoleMode(h, &modeDummy);
}

static void reopen_console_handle(DWORD std, int fd, FILE* stream)
{
    HANDLE handle = GetStdHandle(std);
    if (!is_a_console(handle))
        return;
    if (fd == 0)
        freopen("CONIN$", "rt", stream);
    else
        freopen("CONOUT$", "wt", stream);

    setvbuf(stream, NULL, _IONBF, 0);

    // Set the low-level FD to the new handle value, since mp_subprocess2
    // callers might rely on low-level FDs being set. Note, with this
    // method, fileno(stdin) != STDIN_FILENO, but that shouldn't matter.
    int unbound_fd = -1;
    if (fd == 0)
        unbound_fd = _open_osfhandle((intptr_t) handle, _O_RDONLY);
    else
        unbound_fd = _open_osfhandle((intptr_t) handle, _O_WRONLY);

    // dup2 will duplicate the underlying handle. Don't close unbound_fd,
    // since that will close the original handle.
    if (unbound_fd != -1)
        dup2(unbound_fd, fd);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    int timeout_sec = DEFAULT_TIMEOUT_SEC;
    const WCHAR *target_exe = NULL;
    int first_extra_idx = -1;

    (void)hInstance;
    (void)hPrevInstance;
    (void)pCmdLine;
    (void)nCmdShow;
    int argc;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
        HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
        DWORD modeDummy;

        BOOL stdoutTouched, stderrTouched, stdInTouched;

        if (hOut == NULL) {
            stdoutTouched = FALSE;
        } else if (hOut == INVALID_HANDLE_VALUE) {
            stdoutTouched = FALSE; // ???
        } else if (GetConsoleMode(hOut, &modeDummy)) {
            stdoutTouched = TRUE;
        } else {
            stdoutTouched = TRUE;
        }

        if (hErr == NULL) {
            stderrTouched = FALSE;
        } else if (hErr == INVALID_HANDLE_VALUE) {
            stderrTouched = FALSE; // ???
        } else if (GetConsoleMode(hErr, &modeDummy)) {
            stderrTouched = TRUE;
        } else {
            stderrTouched = TRUE;
        }

        if (hIn == NULL) {
            stdInTouched = FALSE;
        } else if (hIn == INVALID_HANDLE_VALUE) {
            stdInTouched = FALSE; // ???
        } else if (GetConsoleMode(hIn, &modeDummy)) {
            stdInTouched = TRUE;
        } else {
            stdInTouched = TRUE;
        }

        if (!stdoutTouched && !stdInTouched && !stderrTouched) {
            // Attach console from a GUI app, so printing to stdout
            // and stderr works if the app is invoked in a console.
            DWORD attachConsoleRet; 
            attachConsoleRet = AttachConsole(ATTACH_PARENT_PROCESS);
            if (attachConsoleRet != FALSE) {
                // AttachConsole(ATTACH_PARENT_PROCESS) changes STD_*_HANDLE.
                // but it does NOT change CRT stdin/stdout/stderr. Correct them.

                // We have a console window. Redirect input/output streams to that console's
                // low-level handles, so things that use stdio work later on.
                reopen_console_handle(STD_INPUT_HANDLE, 0, stdin);
                reopen_console_handle(STD_OUTPUT_HANDLE, 1, stdout);
                reopen_console_handle(STD_ERROR_HANDLE, 2, stderr);
            }
        }
    }

    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--timeout") == 0 && i + 1 < argc) {
            timeout_sec = _wtoi(argv[i + 1]);
            if (timeout_sec <= 0) timeout_sec = DEFAULT_TIMEOUT_SEC;
            i += 2;
        } else if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            wprintf(L"Usage: tb_win_min_launch.exe [--timeout <sec>] [exe_path] [args...]\n");
            return 0;
        } else if (wcscmp(argv[i], L"--") == 0) {
            i++;
            if (i < argc && !target_exe) { target_exe = argv[i]; i++; }
            if (first_extra_idx < 0 && i < argc) first_extra_idx = i;
            break;
        } else {
            if (!target_exe)
                target_exe = argv[i];
            else if (first_extra_idx < 0)
                first_extra_idx = i;
            i++;
        }
    }

    if (!target_exe) {
        target_exe = find_thunderbird();
        if (!target_exe) {
            fwprintf(stderr, L"Error: Cannot find Thunderbird. Specify the path.\n");
            return 1;
        }
    }

    WCHAR dll_path[MAX_PATH];
    if (!get_dll_path(dll_path, MAX_PATH)) {
        fwprintf(stderr, L"Error: Cannot determine DLL path.\n");
        return 1;
    }
    if (GetFileAttributesW(dll_path) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"Error: Hook DLL not found: %ls\n", dll_path);
        return 1;
    }

    /* Create shared memory */
    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_READWRITE, 0, sizeof(TbSharedData),
                                     TB_SHARED_MEM_NAME);
    if (!hMap) { fwprintf(stderr, L"Error: CreateFileMapping failed\n"); return 1; }
    TbSharedData *shared = (TbSharedData *)MapViewOfFile(
        hMap, FILE_MAP_WRITE, 0, 0, sizeof(TbSharedData));
    if (!shared) { CloseHandle(hMap); return 1; }
    shared->deadline_tick = GetTickCount64() + (ULONGLONG)timeout_sec * 1000;
    wcscpy(shared->dll_path, dll_path);

    HANDLE hReady = CreateEventW(NULL, TRUE, FALSE, TB_READY_EVENT_NAME);

    /* Build command line */
    size_t cmdlen = wcslen(target_exe) + 3;
    if (first_extra_idx > 0)
        for (int j = first_extra_idx; j < argc; j++)
            cmdlen += wcslen(argv[j]) + 3;
    cmdlen += 1;

    WCHAR *cmdline = (WCHAR *)malloc(cmdlen * sizeof(WCHAR));
    if (!cmdline) { fwprintf(stderr, L"Error: out of memory\n"); return 1; }
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

    /* Create process suspended */
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWMINNOACTIVE;

    PROCESS_INFORMATION pi = {0};
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

    /* Inject DLL and wait for hooks */
    int injected = inject_dll(pi.hProcess, dll_path);
    if (injected && hReady)
        WaitForSingleObject(hReady, 5000);

    /* Resume main thread – hooks are in place */
    ResumeThread(pi.hThread);

    // Suppress mouse spinner cursor ("Working in Background" pointer state)
    // now.

    // Gemini says: According to Microsoft's developer documentation, the system turns off the feedback cursor exclusively after the first call to GetMessage, regardless of whether a window is drawn.
    // It may not be correct, but doing this actually works.
    {
        // Post a harmless message directly into your own thread queue
        PostThreadMessage(GetCurrentThreadId(), WM_USER, 0, 0);

        // Immediately consume it. The transition of GetMessage picking up an 
        // actual event terminates the OS feedback timer safely.
        MSG msg;
        if (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }


    // /* Keep shared memory alive until timeout */
    Sleep((DWORD)timeout_sec * 1000);

    UnmapViewOfFile(shared);
    CloseHandle(hMap);
    if (hReady) CloseHandle(hReady);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
