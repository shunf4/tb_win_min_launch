#ifndef TB_WIN_MIN_SHARED_H
#define TB_WIN_MIN_SHARED_H

#include <windows.h>

/* Named kernel objects shared between launcher and DLL */
#define TB_SHARED_MEM_NAME  L"Local\\TbWinMinLaunchShared"
#define TB_READY_EVENT_NAME L"Local\\TbWinMinLaunchReady"

/* Shared data between launcher and injected DLL */
typedef struct {
    /* Absolute time (GetTickCount64) after which hooks become pass-through. */
    ULONGLONG deadline_tick;

    /* Full path to the hook DLL so child-process injection can find it. */
    WCHAR dll_path[MAX_PATH];
} TbSharedData;

#endif /* TB_WIN_MIN_SHARED_H */
