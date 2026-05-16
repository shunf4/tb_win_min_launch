/*
 * tb_win_min_hook.c  –  Injected DLL that hooks window-display APIs so that
 *                       windows created within a time window start minimised.
 *
 * Hooks (applied in two phases):
 *   Phase 1 (immediate, in DLL_PROCESS_ATTACH):
 *     CreateProcessW/A   – inject this DLL into child processes automatically
 *   Phase 2 (deferred, once user32.dll is loaded):
 *     ShowWindow          – redirect show commands to SW_SHOWMINNOACTIVE
 *     CreateWindowExW/A   – strip WS_VISIBLE, add WS_MINIMIZE
 *
 * Hook technique: x64 14-byte absolute jump (mov rax, imm64; jmp rax).
 * For functions that are shorter than 14 bytes at their entry point (e.g.
 * kernel32 stubs that are just `jmp [rip+xxx]`), we hook the actual target
 * in kernelbase.dll / win32u.dll instead.
 *
 * Build (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -shared -O2 -Wall -municode \
 *       -o tb_win_min_hook.dll tb_win_min_hook.c -luser32 -lkernel32
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>
#include "shared.h"

/* ═══════════════════════════ inline hook engine (x64) ═══════════════════ */

/*
 * 14-byte absolute jump:
 *   FF 25 00 00 00 00        jmp [rip+0]
 *   <8 bytes address>
 *
 * Using this form instead of mov rax / jmp rax because:
 *  - doesn't clobber rax
 *  - same size (14 bytes)
 */

#define HOOK_PATCH_SIZE 14
/* We allocate the trampoline separately in a RWX page to be safe. */
#define TRAMPOLINE_ALLOC_SIZE 64

typedef struct {
    void    *target;             /* address of the API we hooked           */
    void    *detour;             /* our replacement function               */
    uint8_t *trampoline;         /* heap alloc'd, RWX: saved bytes + jmp  */
    uint8_t  saved[HOOK_PATCH_SIZE]; /* backup of original bytes           */
    int      installed;
    int      target_size_ok;     /* if the first N bytes disassemble cleanly */
} HookEntry;

/* Build a 14-byte absolute indirect jump to `dest` at `buf`. */
static void build_abs_jmp(uint8_t *buf, void *dest) {
    /* ff 25 00 00 00 00 = jmp [rip+0] */
    buf[0] = 0xFF; buf[1] = 0x25;
    buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00;
    memcpy(buf + 6, &dest, 8);
}

/*
 * Minimal x64 instruction length decoder for the first bytes of Windows API
 * entry points.  Only needs to handle the common patterns found at the start
 * of kernel32/user32/kernelbase functions.  Returns 0 if unrecognised.
 */
static int insn_len(const uint8_t *p) {
    /* Handle common prefixes */
    const uint8_t *start = p;

    /* REX prefix (0x40-0x4F) */
    if (*p >= 0x40 && *p <= 0x4F) p++;

    switch (*p) {
    case 0x90: return (int)(p - start) + 1; /* nop */
    case 0xCC: return (int)(p - start) + 1; /* int3 */

    /* mov reg, imm32 (B8-BF without REX.W) */
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        if (p > start && (start[0] & 0x08)) /* REX.W => imm64 */
            return (int)(p - start) + 1 + 8;
        return (int)(p - start) + 1 + 4;

    /* push reg */
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        return (int)(p - start) + 1;

    /* sub rsp, imm8: 48 83 EC xx */
    case 0x83:
        if (p[1] == 0xEC) return (int)(p - start) + 3;
        return 0;

    /* mov [rsp+imm8], reg: 48 89 4C 24 xx or 48 89 44 24 xx, etc. */
    case 0x89:
        if ((p[1] & 0xC0) == 0x40) { /* [reg+disp8] */
            if ((p[1] & 0x07) == 0x04) /* SIB byte present */
                return (int)(p - start) + 4;
            return (int)(p - start) + 3;
        }
        if ((p[1] & 0xC0) == 0xC0) /* reg, reg */
            return (int)(p - start) + 2;
        if ((p[1] & 0xC0) == 0x00 && (p[1] & 0x07) == 0x04) /* [SIB] */
            return (int)(p - start) + 3;
        return 0;

    /* lea reg, [rip+disp32]:  48 8D 05 xx xx xx xx */
    case 0x8D:
        if ((p[1] & 0xC7) == 0x05) /* [rip+disp32] */
            return (int)(p - start) + 6;
        return 0;

    /* mov reg, [rsp+off8]: 48 8B 44 24 xx */
    case 0x8B:
        if ((p[1] & 0xC0) == 0x40 && (p[1] & 0x07) == 0x04)
            return (int)(p - start) + 4;
        if ((p[1] & 0xC0) == 0xC0)
            return (int)(p - start) + 2;
        return 0;

    /* jmp [rip+disp32]: FF 25 xx xx xx xx */
    case 0xFF:
        if (p[1] == 0x25)
            return (int)(p - start) + 6;
        return 0;

    /* xor reg, reg: 33 C0, 31 C0, etc */
    case 0x33: case 0x31:
        if ((p[1] & 0xC0) == 0xC0)
            return (int)(p - start) + 2;
        return 0;

    /* test ecx,ecx = 85 C9 */
    case 0x85:
        if ((p[1] & 0xC0) == 0xC0)
            return (int)(p - start) + 2;
        return 0;

    /* cmp byte [rip+disp32], imm8: 80 3D xx xx xx xx xx */
    case 0x80:
        if (p[1] == 0x3D)
            return (int)(p - start) + 7;
        return 0;

    default:
        return 0;
    }
}

/*
 * Calculate the minimum number of bytes we need to copy from `target` so that
 * we don't break any instructions.  Returns >= HOOK_PATCH_SIZE on success,
 * 0 if we can't decode enough bytes.
 */
static int calc_stolen_bytes(const uint8_t *target) {
    int total = 0;
    while (total < HOOK_PATCH_SIZE) {
        int n = insn_len(target + total);
        if (n == 0) return 0;
        total += n;
    }
    return total;
}

/*
 * Follow one level of `jmp [rip+disp32]` thunks (kernel32 → kernelbase).
 * Returns the resolved address or the original if not a thunk.
 */
static void *resolve_jmp_stub(void *func) {
    uint8_t *p = (uint8_t *)func;
    /* FF 25 xx xx xx xx = jmp [rip + disp32] */
    if (p[0] == 0xFF && p[1] == 0x25) {
        int32_t disp;
        memcpy(&disp, p + 2, 4);
        void **indirect = (void **)(p + 6 + disp);
        return *indirect;
    }
    return func;
}

static int install_hook(HookEntry *h) {
    DWORD old;

    /* Resolve any jmp-stub so we hook the real function body */
    h->target = resolve_jmp_stub(h->target);

    /* Figure out how many bytes we need to steal */
    int stolen = calc_stolen_bytes((const uint8_t *)h->target);
    if (stolen == 0 || stolen > TRAMPOLINE_ALLOC_SIZE - 14) {
        /* Can't safely decode the prologue — skip this hook */
        h->target_size_ok = 0;
        return 0;
    }
    h->target_size_ok = 1;

    /* Allocate trampoline in a RWX page */
    h->trampoline = (uint8_t *)VirtualAlloc(NULL, TRAMPOLINE_ALLOC_SIZE,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
    if (!h->trampoline) return 0;

    /* Build trampoline: stolen bytes + jump back to target+stolen */
    memcpy(h->trampoline, h->target, stolen);
    void *resume = (uint8_t *)h->target + stolen;
    build_abs_jmp(h->trampoline + stolen, resume);

    /* Save original bytes for unhooking */
    memcpy(h->saved, h->target, HOOK_PATCH_SIZE);

    /* Patch target: write jump to our detour */
    VirtualProtect(h->target, stolen, PAGE_EXECUTE_READWRITE, &old);
    build_abs_jmp((uint8_t *)h->target, h->detour);
    /* NOP out any leftover bytes after the 14-byte jump */
    for (int i = HOOK_PATCH_SIZE; i < stolen; i++)
        ((uint8_t *)h->target)[i] = 0x90;
    VirtualProtect(h->target, stolen, old, &old);
    FlushInstructionCache(GetCurrentProcess(), h->target, stolen);

    h->installed = 1;
    return 1;
}

static void remove_hook(HookEntry *h) {
    if (!h->installed) return;
    DWORD old;
    VirtualProtect(h->target, HOOK_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &old);
    memcpy(h->target, h->saved, HOOK_PATCH_SIZE);
    VirtualProtect(h->target, HOOK_PATCH_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), h->target, HOOK_PATCH_SIZE);
    h->installed = 0;
    /* Don't free trampoline — other threads might still be running through it.
       It's a small leak (64 bytes per hook) that's acceptable for our use case
       since we only hook a few functions. */
}

/* ═══════════════════════════ shared state ════════════════════════════════ */

static ULONGLONG g_deadline = 0;
static WCHAR     g_dll_path[MAX_PATH] = {0};
static volatile LONG g_hooks_active = 0;   /* 1 when phase-2 hooks are up */

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

/* ═══════════════════════════ DLL injection helper ════════════════════════ */

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
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, remote, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return 0;
    }
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return 1;
}

/* ═══════════════════════════ hook entries ════════════════════════════════ */

static HookEntry hook_ShowWindow;
static HookEntry hook_CreateWindowExW;
static HookEntry hook_CreateWindowExA;
static HookEntry hook_CreateProcessW;
static HookEntry hook_CreateProcessA;

/* ─── ShowWindow hook ──────────────────────────────────────────────────── */

typedef BOOL (WINAPI *pfnShowWindow)(HWND, int);

static BOOL WINAPI Hooked_ShowWindow(HWND hWnd, int nCmdShow) {
    pfnShowWindow original = (pfnShowWindow)(void *)hook_ShowWindow.trampoline;
    if (is_within_deadline()) {
        switch (nCmdShow) {
        case SW_SHOW:
        case SW_SHOWNORMAL:
        case SW_SHOWDEFAULT:
        case SW_SHOWNA:
        case SW_SHOWNOACTIVATE:
        case SW_RESTORE:
        case SW_SHOWMAXIMIZED:
            nCmdShow = SW_SHOWMINNOACTIVE;
            break;
        default:
            break;
        }
    }
    return original(hWnd, nCmdShow);
}

/* ─── CreateWindowExW hook ─────────────────────────────────────────────── */

typedef HWND (WINAPI *pfnCreateWindowExW)(
    DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int,
    HWND, HMENU, HINSTANCE, LPVOID);

static HWND WINAPI Hooked_CreateWindowExW(
    DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName,
    DWORD dwStyle, int X, int Y, int nWidth, int nHeight,
    HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    pfnCreateWindowExW original =
        (pfnCreateWindowExW)(void *)hook_CreateWindowExW.trampoline;

    if (is_within_deadline() && hWndParent == NULL) {
        /* Top-level window: strip WS_VISIBLE so it doesn't flash,
           add WS_MINIMIZE */
        if (dwStyle & WS_VISIBLE) {
            dwStyle &= ~WS_VISIBLE;
            dwStyle |= WS_MINIMIZE;
        }
    }

    return original(dwExStyle, lpClassName, lpWindowName, dwStyle,
                    X, Y, nWidth, nHeight, hWndParent, hMenu,
                    hInstance, lpParam);
}

/* ─── CreateWindowExA hook ─────────────────────────────────────────────── */

typedef HWND (WINAPI *pfnCreateWindowExA)(
    DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int,
    HWND, HMENU, HINSTANCE, LPVOID);

static HWND WINAPI Hooked_CreateWindowExA(
    DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName,
    DWORD dwStyle, int X, int Y, int nWidth, int nHeight,
    HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    pfnCreateWindowExA original =
        (pfnCreateWindowExA)(void *)hook_CreateWindowExA.trampoline;

    if (is_within_deadline() && hWndParent == NULL) {
        if (dwStyle & WS_VISIBLE) {
            dwStyle &= ~WS_VISIBLE;
            dwStyle |= WS_MINIMIZE;
        }
    }

    return original(dwExStyle, lpClassName, lpWindowName, dwStyle,
                    X, Y, nWidth, nHeight, hWndParent, hMenu,
                    hInstance, lpParam);
}

/* ─── CreateProcessW hook ──────────────────────────────────────────────── */

typedef BOOL (WINAPI *pfnCreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApp, LPWSTR lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCWSTR lpDir,
    LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    pfnCreateProcessW original =
        (pfnCreateProcessW)(void *)hook_CreateProcessW.trampoline;

    if (!is_within_deadline()) {
        return original(lpApp, lpCmd, lpPA, lpTA, bInherit,
                        dwFlags, lpEnv, lpDir, lpSI, lpPI);
    }

    /* Force suspended so we can inject before the child runs */
    int was_suspended = (dwFlags & CREATE_SUSPENDED) != 0;
    dwFlags |= CREATE_SUSPENDED;

    /* Also request minimised start */
    STARTUPINFOW si_copy = {0};
    if (lpSI) {
        memcpy(&si_copy, lpSI, lpSI->cb <= sizeof(si_copy) ? lpSI->cb : sizeof(si_copy));
    }
    si_copy.cb = sizeof(si_copy);
    si_copy.dwFlags |= STARTF_USESHOWWINDOW;
    si_copy.wShowWindow = SW_SHOWMINNOACTIVE;

    PROCESS_INFORMATION pi_local = {0};
    BOOL ret = original(lpApp, lpCmd, lpPA, lpTA, bInherit,
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

/* ─── CreateProcessA hook ──────────────────────────────────────────────── */

typedef BOOL (WINAPI *pfnCreateProcessA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static BOOL WINAPI Hooked_CreateProcessA(
    LPCSTR lpApp, LPSTR lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCSTR lpDir,
    LPSTARTUPINFOA lpSI, LPPROCESS_INFORMATION lpPI)
{
    pfnCreateProcessA original =
        (pfnCreateProcessA)(void *)hook_CreateProcessA.trampoline;

    if (!is_within_deadline()) {
        return original(lpApp, lpCmd, lpPA, lpTA, bInherit,
                        dwFlags, lpEnv, lpDir, lpSI, lpPI);
    }

    int was_suspended = (dwFlags & CREATE_SUSPENDED) != 0;
    dwFlags |= CREATE_SUSPENDED;

    STARTUPINFOA si_copy = {0};
    if (lpSI) {
        memcpy(&si_copy, lpSI, lpSI->cb <= sizeof(si_copy) ? lpSI->cb : sizeof(si_copy));
    }
    si_copy.cb = sizeof(si_copy);
    si_copy.dwFlags |= STARTF_USESHOWWINDOW;
    si_copy.wShowWindow = SW_SHOWMINNOACTIVE;

    PROCESS_INFORMATION pi_local = {0};
    BOOL ret = original(lpApp, lpCmd, lpPA, lpTA, bInherit,
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

/* ═══════════════════════════ hook installation ═══════════════════════════ */

static void install_phase1_hooks(void) {
    /* CreateProcess hooks — kernel32 is always loaded */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        hook_CreateProcessW.target = (void *)GetProcAddress(hKernel32, "CreateProcessW");
        hook_CreateProcessW.detour = (void *)Hooked_CreateProcessW;
        if (hook_CreateProcessW.target) install_hook(&hook_CreateProcessW);

        hook_CreateProcessA.target = (void *)GetProcAddress(hKernel32, "CreateProcessA");
        hook_CreateProcessA.detour = (void *)Hooked_CreateProcessA;
        if (hook_CreateProcessA.target) install_hook(&hook_CreateProcessA);
    }
}

static void install_phase2_hooks(void) {
    /* user32 hooks — only when user32 is loaded */
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) {
        /* Try to load it ourselves; it's fine since the process will need it anyway */
        hUser32 = LoadLibraryW(L"user32.dll");
    }
    if (hUser32) {
        hook_ShowWindow.target = (void *)GetProcAddress(hUser32, "ShowWindow");
        hook_ShowWindow.detour = (void *)Hooked_ShowWindow;
        if (hook_ShowWindow.target) install_hook(&hook_ShowWindow);

        hook_CreateWindowExW.target = (void *)GetProcAddress(hUser32, "CreateWindowExW");
        hook_CreateWindowExW.detour = (void *)Hooked_CreateWindowExW;
        if (hook_CreateWindowExW.target) install_hook(&hook_CreateWindowExW);

        hook_CreateWindowExA.target = (void *)GetProcAddress(hUser32, "CreateWindowExA");
        hook_CreateWindowExA.detour = (void *)Hooked_CreateWindowExA;
        if (hook_CreateWindowExA.target) install_hook(&hook_CreateWindowExA);
    }
    InterlockedExchange(&g_hooks_active, 1);
}

static void remove_all_hooks(void) {
    remove_hook(&hook_ShowWindow);
    remove_hook(&hook_CreateWindowExW);
    remove_hook(&hook_CreateWindowExA);
    remove_hook(&hook_CreateProcessW);
    remove_hook(&hook_CreateProcessA);
}

/* ═══════════════════════════ worker thread ═══════════════════════════════ */

static DWORD WINAPI hook_worker_thread(LPVOID param) {
    (void)param;

    /* Phase 2: install user32 hooks.
       If user32 isn't loaded yet, poll briefly — the process will load it
       soon when it initialises its GUI. */
    for (int attempt = 0; attempt < 100 && is_within_deadline(); attempt++) {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (hUser32) break;
        Sleep(10);
    }
    install_phase2_hooks();

    /* Signal the launcher that hooks are installed */
    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, TB_READY_EVENT_NAME);
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }

    /* Wait until deadline then unhook */
    ULONGLONG now = GetTickCount64();
    if (now < g_deadline) {
        Sleep((DWORD)(g_deadline - now));
    }

    remove_all_hooks();
    return 0;
}

/* ═══════════════════════════ DLL entry point ═════════════════════════════ */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        if (!load_shared_data()) return TRUE;
        if (!is_within_deadline()) return TRUE;

        /* Phase 1: hook CreateProcess immediately (kernel32 is always present) */
        install_phase1_hooks();

        /* Spawn worker for phase 2 hooks + cleanup.
           We can't do LoadLibrary(user32) in DllMain due to loader lock,
           so we defer it to a thread. */
        CreateThread(NULL, 0, hook_worker_thread, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        remove_all_hooks();
        break;
    }
    return TRUE;
}
