import sys
from pathlib import Path

here = Path(__file__).resolve().parent.parent
pidfile = here / 'honeypot.pid'
if not pidfile.exists():
    print('PID file not found:', pidfile)
    sys.exit(1)
pid = int(pidfile.read_text())

if sys.platform == 'win32':
    # Use ctypes to call TerminateProcess via OpenProcess for a safer shutdown.
    import ctypes
    import ctypes.wintypes as wintypes

    PROCESS_TERMINATE = 0x0001

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    TerminateProcess = kernel32.TerminateProcess
    TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    TerminateProcess.restype = wintypes.BOOL

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    h = OpenProcess(PROCESS_TERMINATE, False, int(pid))
    if not h:
        print('Failed to open process', pid)
        pidfile.unlink(missing_ok=True)
        sys.exit(1)
    try:
        ok = TerminateProcess(h, 0)
        if not ok:
            print('TerminateProcess failed')
        else:
            print('Terminated process', pid)
    finally:
        CloseHandle(h)
else:
    # Unix-like fallback
    import os, signal
    try:
        os.kill(pid, signal.SIGTERM)
        print('Sent SIGTERM to', pid)
    except Exception as e:
        print('Failed to send SIGTERM:', e)

pidfile.unlink(missing_ok=True)
print('Removed PID file')
