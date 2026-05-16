### tb_win_min_launch

> [!WARNING]
> This is a half-vibe-coded (a large part written by LLM, reviewed and manually
> modified) tool.

A tool that injects, hooks and launches Thunderbird Mail x64 on Windows in
**minimized** mode.

Because Thunderbird Mail (also Firefox from Mozilla) doesn't respect
SW_MINIMIZE flag (that is, when you select "Start Minimized" in a shortcut)
when run as a process, possibly because it builds and brings
up the window in some background task/logic, which is a bit of nuisance to me.
Also see [this Mozilla Connect issue](https://connect.mozilla.org/t5/ideas/add-option-to-start-thunderbird-on-minimized-system-startup/idi-p/36288).

Build the tool with MinGW-w64 toolchain (I am using the one in Cygwin),
and start `tb_win_min_launch.exe`, and that should launch Thunderbird Mail
in C: drive (for other paths, see `--help` for ways to specify its path)
in minimized window.

Note: the tool only applies to (only tested in) Thunderbird Mail **x64**
version. Please inspect the specific .exe executable file for its arch, not by
looking at whether it's in `Program Files (x86)`. For x86 version, you may find
way to build it as x86 version.

The tool launches `thunderbird.exe`, injects a remote thread to it, make it
load a dynamic library DLL and hook (via MinHook) `ShowWindow`, `CreateProcess`
(so child processes are hooked also) winapi calls in 10 seconds. In this time
range, all calls to `ShowWindow` would be modified to force it minimized.
