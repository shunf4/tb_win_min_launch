CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -Wall -municode
LDFLAGS_EXE = -lkernel32 -luser32
LDFLAGS_DLL = -lkernel32 -luser32

all: tb_win_min_launch.exe tb_win_min_hook.dll

tb_win_min_launch.exe: tb_win_min_launch.c shared.h
	$(CC) $(CFLAGS) -o $@ tb_win_min_launch.c $(LDFLAGS_EXE)

tb_win_min_hook.dll: tb_win_min_hook.c shared.h
	$(CC) $(CFLAGS) -shared -o $@ tb_win_min_hook.c $(LDFLAGS_DLL)

clean:
	rm -f tb_win_min_launch.exe tb_win_min_hook.dll

.PHONY: all clean
