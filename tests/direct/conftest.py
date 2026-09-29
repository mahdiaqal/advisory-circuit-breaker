import inspect
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def defer_loader_temp_unlink_on_windows(monkeypatch):
    if os.name != "nt":
        yield
        return
    original = os.unlink
    deferred = []
    temp_root = Path(tempfile.gettempdir()).resolve()

    def unlink(path, *args, **kwargs):
        try:
            return original(path, *args, **kwargs)
        except PermissionError as exc:
            caller = inspect.currentframe().f_back.f_code.co_name
            resolved = Path(path).resolve()
            if getattr(exc, "winerror", None) != 32 or caller != "_inject_message_to_fd0":
                raise
            if resolved.parent != temp_root or not resolved.name.startswith("tmp"):
                raise
            deferred.append(resolved)

    monkeypatch.setattr(os, "unlink", unlink)
    yield
    for path in deferred:
        try:
            original(path)
        except FileNotFoundError:
            pass
