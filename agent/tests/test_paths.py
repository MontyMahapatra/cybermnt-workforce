"""
Regression test for the __file__-vs-frozen-exe path bug. Doesn't need
Windows or a real build -- it just monkeypatches sys.frozen the same way
PyInstaller sets it at runtime, and confirms get_app_dir() responds
correctly either way.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import monitor_agent  # noqa: E402


def test_app_dir_uses_file_location_when_not_frozen(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    result = monitor_agent.get_app_dir()
    assert result == Path(monitor_agent.__file__).parent


def test_app_dir_uses_executable_location_when_frozen(monkeypatch, tmp_path):
    fake_exe = tmp_path / "CyberMNT-Agent.exe"
    fake_exe.touch()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe), raising=False)

    result = monitor_agent.get_app_dir()
    assert result == tmp_path
    # The bug this guards against: falling back to __file__'s location
    # (a temp extraction dir under PyInstaller) instead of the exe's
    # actual folder.
    assert result != Path(monitor_agent.__file__).parent
