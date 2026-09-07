"""
Cross-platform system state helpers for the monitoring agent.

Every function here degrades gracefully: if a platform-specific dependency
isn't installed, we return a safe "unknown" value and log a warning rather
than crashing the agent. Better to under-report than to take down the
agent process on a machine missing an optional library.
"""

import platform
import shutil
import subprocess
import logging

log = logging.getLogger("cybermnt-agent.platform")

SYSTEM = platform.system()  # "Windows", "Darwin", "Linux"


def get_idle_seconds() -> float | None:
    """Seconds since the last keyboard/mouse input. None if we can't tell."""
    try:
        if SYSTEM == "Windows":
            return _idle_windows()
        elif SYSTEM == "Darwin":
            return _idle_macos()
        elif SYSTEM == "Linux":
            return _idle_linux()
    except Exception as e:
        log.warning("Idle-time detection failed (%s): %s", SYSTEM, e)
    return None


def get_active_window_info() -> dict:
    """Best-effort {'app': str, 'title_category': str}. Never raw window
    titles/URLs by default -- see README for why that's a deliberate
    scope decision, not a limitation."""
    try:
        if SYSTEM == "Windows":
            return _active_window_windows()
        elif SYSTEM == "Darwin":
            return _active_window_macos()
        elif SYSTEM == "Linux":
            return _active_window_linux()
    except Exception as e:
        log.warning("Active-window detection failed (%s): %s", SYSTEM, e)
    return {"app": "unknown", "title_category": "unknown"}


# ---------------------------------------------------------------- Windows --
def _idle_windows() -> float:
    import ctypes

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
    millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
    return millis / 1000.0


def _active_window_windows() -> dict:
    import win32gui  # requires pywin32
    import win32process
    import psutil

    hwnd = win32gui.GetForegroundWindow()
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    proc_name = psutil.Process(pid).name() if pid else "unknown"
    return {"app": proc_name, "title_category": _categorize(proc_name)}


# ------------------------------------------------------------------ macOS --
def _idle_macos() -> float:
    import Quartz  # requires pyobjc-framework-Quartz

    return Quartz.CGEventSourceSecondsSinceLastEventType(
        Quartz.kCGEventSourceStateHIDSystemState, Quartz.kCGAnyInputEventType
    )


def _active_window_macos() -> dict:
    from AppKit import NSWorkspace  # requires pyobjc-framework-AppKit

    app = NSWorkspace.sharedWorkspace().frontmostApplication()
    name = app.localizedName() if app else "unknown"
    return {"app": name, "title_category": _categorize(name)}


# ------------------------------------------------------------------ Linux --
def _idle_linux() -> float | None:
    # X11 desktops: xprintidle reports milliseconds idle. Wayland has no
    # universal equivalent -- this is a known, documented gap.
    if shutil.which("xprintidle"):
        out = subprocess.check_output(["xprintidle"], timeout=2)
        return int(out.strip()) / 1000.0
    log.warning("xprintidle not found and/or non-X11 session; idle time unavailable")
    return None


def _active_window_linux() -> dict:
    if shutil.which("wmctrl") and shutil.which("xdotool"):
        win_id = subprocess.check_output(
            ["xdotool", "getactivewindow"], timeout=2
        ).strip()
        wm_list = subprocess.check_output(["wmctrl", "-lp"], timeout=2).decode()
        for line in wm_list.splitlines():
            if line.startswith(win_id.decode()):
                app = line.split(None, 4)[-1]
                return {"app": app, "title_category": _categorize(app)}
    return {"app": "unknown", "title_category": "unknown"}


# --------------------------------------------------------------- shared ---
_PRODUCTIVE = {"code", "terminal", "iterm2", "slack", "outlook", "excel",
               "word", "chrome-devtools", "pycharm", "vim", "docker"}
_NEUTRAL = {"chrome", "firefox", "safari", "explorer", "finder", "msedge"}


def _categorize(app_name: str) -> str:
    """Coarse, non-invasive bucket. Deliberately does not look at window
    titles/tabs/URLs -- browsers land in 'neutral' regardless of what's
    open in them, on purpose."""
    name = (app_name or "").lower()
    if any(k in name for k in _PRODUCTIVE):
        return "productive"
    if any(k in name for k in _NEUTRAL):
        return "neutral"
    return "other"
