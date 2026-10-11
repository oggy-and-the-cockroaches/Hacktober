"""Debian (.deb) Package Builder for Shipcheck."""

import os
import io
import time
import tarfile
import gzip
from pathlib import Path


def create_tar_gz(files_dict):
    """Create in-memory .tar.gz from dictionary of {relative_path: (content_bytes, mode)}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, (data, mode) in files_dict.items():
            ti = tarfile.TarInfo(name=path)
            ti.size = len(data)
            ti.mtime = int(time.time())
            ti.mode = mode
            ti.uname = "root"
            ti.gname = "root"
            ti.uid = 0
            ti.gid = 0
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def create_ar_member(name: str, data: bytes, mtime: int = None, mode: int = 0o100644) -> bytes:
    """Format a single member for the standard Debian 'ar' archive."""
    if mtime is None:
        mtime = int(time.time())
    
    # Name must be formatted to 16 bytes
    # Standard debian uses name padded with spaces
    name_field = f"{name:<16}".encode("ascii")
    mtime_field = f"{mtime:<12}".encode("ascii")
    owner_field = f"0     ".encode("ascii")
    group_field = f"0     ".encode("ascii")
    mode_field = f"{oct(mode)[2:]:<8}".encode("ascii")
    size_field = f"{len(data):<10}".encode("ascii")
    trailer = b"`\n"

    header = name_field + mtime_field + owner_field + group_field + mode_field + size_field + trailer
    assert len(header) == 60, f"AR header must be 60 bytes, got {len(header)}"

    member = header + data
    if len(data) % 2 != 0:
        member += b"\n"  # 2-byte alignment padding in ar archive
    return member


def build_deb_package(output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. debian-binary
    debian_binary = b"2.0\n"

    # 2. control.tar.gz
    control_content = """Package: shipcheck
Version: 1.0.0
Section: devel
Priority: optional
Architecture: amd64
Maintainer: Shipcheck Core Team <team@shipcheck.io>
Depends: python3 (>= 3.10), curl, libc6 (>= 2.31)
Homepage: https://shipcheck.io
Description: Pre-deployment Security & Sentinel C++ RASP Platform
 Shipcheck delivers enterprise-grade pre-deployment static analysis,
 vulnerability auto-remediation powered by Gemini AI, and zero-overhead
 Hyperion C++ WAF and runtime application self-protection (RASP).
""".encode("utf-8")

    postinst_script = """#!/bin/bash
set -e
echo "=========================================================="
echo "  Shipcheck Pre-Deployment Security Platform installed!   "
echo "  Run 'shipcheck' from any terminal to launch dashboard.  "
echo "=========================================================="
exit 0
""".encode("utf-8")

    control_files = {
        "./control": (control_content, 0o644),
        "./postinst": (postinst_script, 0o755),
    }
    control_tar_gz = create_tar_gz(control_files)

    # 3. data.tar.gz
    launcher_script = """#!/usr/bin/env bash
# Shipcheck Linux Launcher
set -e

echo "========================================================================"
echo "   ____ _     _             _               _                         "
echo "  / ___| |__ (_)_ __   ___| |__   ___  ___| | __                      "
echo "  \\___ \\| '_ \\| | '_ \\ / __| '_ \\ / _ \\/ __| |/ /                     "
echo "   ___) | | | | | |_) | (__| | | |  __/ (__|   <                      "
echo "  |____/|_| |_|_| .__/ \\___|_| |_|\\___|\\___|_|\\_\\                     "
echo "                |_|                                                   "
echo "   Pre-deployment Security & Sentinel RASP Platform                   "
echo "========================================================================"
echo "   ⚡ Launching Shipcheck Service on http://127.0.0.1:8000..."

PORT="${SHIPCHECK_PORT:-8000}"

# Try system browser
if command -v xdg-open > /dev/null; then
    (sleep 1.5 && xdg-open "http://127.0.0.1:${PORT}") &
elif command -v sensible-browser > /dev/null; then
    (sleep 1.5 && sensible-browser "http://127.0.0.1:${PORT}") &
fi

exec python3 -m uvicorn backend.main:app --host 127.0.0.1 --port "$PORT"
""".encode("utf-8")

    desktop_file = """[Desktop Entry]
Name=Shipcheck Security
Comment=Pre-deployment Security & Sentinel RASP Platform
Exec=/usr/local/bin/shipcheck
Icon=security-high
Terminal=true
Type=Application
Categories=Development;Security;
""".encode("utf-8")

    data_files = {
        "./usr/local/bin/shipcheck": (launcher_script, 0o755),
        "./usr/share/applications/shipcheck.desktop": (desktop_file, 0o644),
    }
    data_tar_gz = create_tar_gz(data_files)

    # Assemble .deb file (ar archive)
    ar_magic = b"!<arch>\n"
    deb_bytes = (
        ar_magic
        + create_ar_member("debian-binary", debian_binary)
        + create_ar_member("control.tar.gz", control_tar_gz)
        + create_ar_member("data.tar.gz", data_tar_gz)
    )

    with open(output_path, "wb") as f:
        f.write(deb_bytes)

    print(f"[SUCCESS] Built Debian package: {output_path} ({len(deb_bytes):,} bytes)")


if __name__ == "__main__":
    out = Path("dist/shipcheck_1.0.0_amd64.deb")
    build_deb_package(out)
