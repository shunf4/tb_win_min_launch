CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -Wall -municode
LDFLAGS_EXE = -lkernel32 -luser32 -lshlwapi
LDFLAGS_DLL = -lkernel32 -luser32

MINHOOK_DIR = minhook
MINHOOK_INC = -I$(MINHOOK_DIR)/include -I$(MINHOOK_DIR)/src
MINHOOK_SRC = $(MINHOOK_DIR)/src/hook.c \
              $(MINHOOK_DIR)/src/buffer.c \
              $(MINHOOK_DIR)/src/trampoline.c \
              $(MINHOOK_DIR)/src/hde/hde64.c

all: tb_win_min_launch.exe tb_win_min_hook.dll

tb_win_min_launch.exe: tb_win_min_launch.c shared.h
	$(CC) $(CFLAGS) -mwindows -o $@ tb_win_min_launch.c $(LDFLAGS_EXE)

tb_win_min_hook.dll: tb_win_min_hook.c shared.h $(MINHOOK_SRC)
	$(CC) $(CFLAGS) -shared $(MINHOOK_INC) -o $@ tb_win_min_hook.c $(MINHOOK_SRC) $(LDFLAGS_DLL)

clean:
	rm -f tb_win_min_launch.exe tb_win_min_hook.dll

.PHONY: all clean
