"""Optional ctypes bridge for Shipcheck's high-performance Hyperion C++ Engine (v3.0).

Exposes:
  - WAF multi-pattern Aho-Corasick inspection (O(N) single pass)
  - In-place URL decoding
  - Integer-triplet SemVer matching
  - Zero-dependency RFC 6234 SHA-256 hashing
  - RASP SQL token inspection
  - High-entropy secret & prefix scanner
"""

import ctypes
import hashlib
import os
import re
from pathlib import Path
from typing import Optional, Union


class NativeInspector:
    """Uses the native C++ engine when built; callers retain Python fallback."""

    _labels = {
        1 << 0: "Blind SQL injection",
        1 << 1: "HTML injection",
        1 << 2: "Server-side includes injection",
        1 << 3: "Server-side template injection",
        1 << 4: "XPath injection",
        1 << 5: "Remote code execution",
        1 << 6: "OS command injection",
        1 << 7: "XML injection",
        1 << 8: "LDAP injection",
        1 << 9: "CRLF injection",
        1 << 10: "SQL injection",
        1 << 11: "Cross-site scripting",
        1 << 12: "Path traversal",
    }

    _sql_labels = {
        1 << 0: "UNION injection",
        1 << 1: "DROP TABLE",
        1 << 2: "DELETE without WHERE",
        1 << 3: "UPDATE without WHERE",
        1 << 4: "Tautology (OR 1=1)",
        1 << 5: "Stacked query",
        1 << 6: "EXEC xp_cmdshell",
        1 << 7: "OUTFILE export",
        1 << 8: "INFORMATION_SCHEMA query",
        1 << 9: "Sleep / Benchmark injection",
    }

    _secret_labels = {
        1 << 0: "High entropy token",
        1 << 1: "AWS access key",
        1 << 2: "GitHub personal token",
        1 << 3: "Stripe live API key",
        1 << 4: "Slack token",
        1 << 5: "Generic API secret key",
        1 << 6: "Private key PEM block",
        1 << 7: "JSON Web Token (JWT)",
    }

    def __init__(self):
        self._library: Optional[ctypes.CDLL] = None
        self._version: str = "python-fallback"
        suffix = ".dll" if os.name == "nt" else ".so"
        import sys
        if getattr(sys, "frozen", False):
            base_dir = Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
            native_dir = base_dir / "backend" / "native"
            if not native_dir.exists():
                native_dir = base_dir / "native"
        else:
            native_dir = Path(__file__).resolve().parents[1] / "native"

        # Search candidates in priority order
        candidates = []
        if native_dir.exists():
            candidates.extend(sorted(native_dir.glob(f"shipcheck_engine_v*{suffix}"), reverse=True))
            candidates.extend(sorted(native_dir.glob(f"shipcheck_inspector_v*{suffix}"), reverse=True))
            candidates.append(native_dir / f"shipcheck_engine{suffix}")
            candidates.append(native_dir / f"shipcheck_inspector{suffix}")

        for library_path in candidates:
            if library_path.exists():
                try:
                    library = ctypes.CDLL(str(library_path))
                    self._bind_functions(library)
                    self._library = library
                    self._version = library_path.name
                    break
                except Exception:
                    continue

    def _bind_functions(self, library: ctypes.CDLL):
        # 1. WAF Inspection
        if hasattr(library, "sc_waf_init"):
            library.sc_waf_init()
        if hasattr(library, "sc_waf_inspect"):
            library.sc_waf_inspect.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
            library.sc_waf_inspect.restype = ctypes.c_uint32
        elif hasattr(library, "shipcheck_inspect"):
            library.shipcheck_inspect.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
            library.shipcheck_inspect.restype = ctypes.c_uint32

        # 2. URL Decode
        if hasattr(library, "sc_url_decode"):
            library.sc_url_decode.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
            library.sc_url_decode.restype = ctypes.c_size_t

        # 3. SemVer Match
        if hasattr(library, "sc_semver_match"):
            library.sc_semver_match.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
            library.sc_semver_match.restype = ctypes.c_int

        # 4. SHA-256
        if hasattr(library, "sc_sha256"):
            library.sc_sha256.argtypes = (ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p)
            library.sc_sha256.restype = None

        # 5. SQL Inspect
        if hasattr(library, "sc_sql_inspect"):
            library.sc_sql_inspect.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
            library.sc_sql_inspect.restype = ctypes.c_uint32

        # 6. Secret Scanner
        if hasattr(library, "sc_secret_scan"):
            library.sc_secret_scan.argtypes = (ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_double)
            library.sc_secret_scan.restype = ctypes.c_uint32

        # Version
        if hasattr(library, "sc_engine_version"):
            library.sc_engine_version.restype = ctypes.c_char_p
            try:
                self._version = library.sc_engine_version().decode("utf-8", errors="ignore")
            except Exception:
                self._version = "unknown-c++"
        elif hasattr(library, "shipcheck_engine_version"):
            library.shipcheck_engine_version.restype = ctypes.c_char_p
            try:
                self._version = library.shipcheck_engine_version().decode("utf-8", errors="ignore")
            except Exception:
                self._version = "unknown-c++"

    @property
    def available(self) -> bool:
        return self._library is not None

    @property
    def version(self) -> str:
        return self._version

    def inspect(self, value: Union[bytes, str]) -> list[str]:
        """Inspect a request payload for attack signatures."""
        if not value:
            return []
        if isinstance(value, str):
            data = value.encode("utf-8", errors="ignore")
        else:
            data = value

        if self._library:
            if hasattr(self._library, "sc_waf_inspect"):
                mask = self._library.sc_waf_inspect(data, len(data))
                return [label for bit, label in self._labels.items() if mask & bit]
            elif hasattr(self._library, "shipcheck_inspect"):
                mask = self._library.shipcheck_inspect(data, len(data))
                return [label for bit, label in self._labels.items() if mask & bit]

        # Python fallback regex
        return []

    def url_decode(self, value: Union[bytes, str]) -> str:
        """Fast in-place URL decoding."""
        if not value:
            return ""
        if isinstance(value, str):
            raw = value.encode("utf-8", errors="ignore")
        else:
            raw = value

        if self._library and hasattr(self._library, "sc_url_decode"):
            buf = ctypes.create_string_buffer(raw, len(raw) + 1)
            new_len = self._library.sc_url_decode(buf, len(raw))
            return buf.raw[:new_len].decode("utf-8", errors="replace")

        import urllib.parse
        return urllib.parse.unquote_plus(value if isinstance(value, str) else value.decode("utf-8", errors="replace"))

    def semver_match(self, installed: str, constraint: str) -> bool:
        """Check if an installed semver version matches an advisory constraint."""
        if not installed or not constraint:
            return False
        if self._library and hasattr(self._library, "sc_semver_match"):
            res = self._library.sc_semver_match(
                installed.strip().encode("utf-8"),
                constraint.strip().encode("utf-8")
            )
            return res == 1

        # Basic Python fallback
        try:
            from packaging.version import parse as vparse
            from packaging.specifiers import SpecifierSet
            return vparse(installed) in SpecifierSet(constraint)
        except Exception:
            return False

    def sha256(self, data: Union[bytes, str]) -> str:
        """Fast RFC 6234 SHA-256 hash."""
        if isinstance(data, str):
            raw = data.encode("utf-8", errors="ignore")
        else:
            raw = data

        if self._library and hasattr(self._library, "sc_sha256"):
            buf = ctypes.create_string_buffer(65)
            self._library.sc_sha256(raw, len(raw), buf)
            return buf.value.decode("ascii")

        return hashlib.sha256(raw).hexdigest()

    def sql_inspect(self, query: Union[bytes, str]) -> list[str]:
        """Inspect a SQL query for dangerous statements, tautologies, and stacked queries."""
        if not query:
            return []
        if isinstance(query, str):
            data = query.encode("utf-8", errors="ignore")
        else:
            data = query

        if self._library and hasattr(self._library, "sc_sql_inspect"):
            mask = self._library.sc_sql_inspect(data, len(data))
            return [label for bit, label in self._sql_labels.items() if mask & bit]

        # Python fallback checks
        text = data.decode("utf-8", errors="ignore").upper()
        detected = []
        if "UNION" in text and "SELECT" in text:
            detected.append("UNION injection")
        if re.search(r"\bDROP\s+TABLE\b", text):
            detected.append("DROP TABLE")
        if re.search(r"\bOR\s+1\s*=\s*1\b", text):
            detected.append("Tautology (OR 1=1)")
        return detected

    def secret_scan(self, content: Union[bytes, str], min_token_len: int = 20, entropy_threshold: float = 4.0) -> list[str]:
        """Scan buffer for leaked secret keys, tokens, and high-entropy credentials."""
        if not content:
            return []
        if isinstance(content, str):
            data = content.encode("utf-8", errors="ignore")
        else:
            data = content

        if self._library and hasattr(self._library, "sc_secret_scan"):
            mask = self._library.sc_secret_scan(data, len(data), min_token_len, entropy_threshold)
            return [label for bit, label in self._secret_labels.items() if mask & bit]

        return []


native_inspector = NativeInspector()
