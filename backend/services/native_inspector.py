"""Optional ctypes bridge for Shipcheck's low-latency native request inspector."""

import ctypes
import os
from pathlib import Path
from typing import Optional


class NativeInspector:
    """Uses the native engine when built; callers retain their regex fallback."""
    _labels = {
        1 << 0: "Blind SQL injection", 1 << 1: "HTML injection",
        1 << 2: "Server-side includes injection", 1 << 3: "Server-side template injection",
        1 << 4: "XPath injection", 1 << 5: "Remote code execution",
        1 << 6: "OS command injection", 1 << 7: "XML injection",
        1 << 8: "LDAP injection", 1 << 9: "CRLF injection",
    }

    def __init__(self):
        self._library: Optional[ctypes.CDLL] = None
        suffix = ".dll" if os.name == "nt" else ".so"
        native_dir = Path(__file__).resolve().parents[1] / "native"
        # Versioned names let a development reloader keep an older DLL open.
        candidates = sorted(native_dir.glob(f"shipcheck_inspector_v*{suffix}"), reverse=True)
        candidates.append(native_dir / f"shipcheck_inspector{suffix}")
        library_path = next((item for item in candidates if item.exists()), None)
        if library_path:
            library = ctypes.CDLL(str(library_path))
            library.shipcheck_inspect.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
            library.shipcheck_inspect.restype = ctypes.c_uint32
            self._library = library

    @property
    def available(self) -> bool:
        return self._library is not None

    def inspect(self, value: bytes) -> list[str]:
        if not self._library or not value:
            return []
        mask = self._library.shipcheck_inspect(value, len(value))
        return [label for bit, label in self._labels.items() if mask & bit]


native_inspector = NativeInspector()
