"""PyInstaller specification and build script for Shipcheck executable."""

import os
import sys
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
PYTHON_EXE = sys.executable

def build():
    print("[*] Starting Shipcheck executable compilation...")

    # Ensure frontend directory exists
    frontend_dir = ROOT_DIR / "frontend"
    native_dir = ROOT_DIR / "backend" / "native"
    
    # Check native DLLs
    dll_files = list(native_dir.glob("*.dll"))
    print(f"[*] Found native DLLs: {[d.name for d in dll_files]}")

    # Build PyInstaller command line arguments
    cmd = [
        PYTHON_EXE, "-m", "PyInstaller",
        "--name=Shipcheck",
        "--noconfirm",
        "--onedir",  # fast startup and easy debugging, or onefile if preferred
        "--console",  # keep terminal console window active so user can view logs and stop with CTRL+C
        "--add-data", f"{frontend_dir};frontend",
    ]

    # Add native dlls if present
    if native_dir.exists():
        cmd.extend(["--add-data", f"{native_dir};backend/native"])

    # Hidden imports
    hidden_imports = [
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "fastapi",
        "starlette",
        "starlette.routing",
        "starlette.staticfiles",
        "starlette.responses",
        "starlette.middleware",
        "starlette.middleware.cors",
        "pydantic",
        "pydantic.deprecated",
        "pydantic_core",
        "anyio",
        "anyio._backends._asyncio",
        "sqlite3",
        "ctypes",
        "backend",
        "backend.main",
        "backend.database.schema",
        "backend.services",
        "backend.services.native_inspector",
        "backend.services.runtime_monitoring",
        "backend.services.scanner",
        "backend.services.llm",
        "backend.services.workspace",
        "backend.services.ai_cache",
        "backend.services.remediation",
        "backend.services.sandbox",
        "backend.api",
        "backend.api.projects",
        "backend.api.scans",
        "backend.api.reports",
        "backend.api.runtime",
        "backend.api.proxy",
        "backend.api.fixes",
        "backend.api.sentinel",
        "backend.api.sandbox",
        "backend.api.remediation",
        "backend.scanners",
        "backend.scanners.security",
        "backend.scanners.privacy",
        "backend.scanners.reliability",
        "backend.scanners.production",
        "backend.scanners.dependency",
        "backend.scanners.configuration",
        "backend.scanners.runtime",
        "backend.scanners.ai_reasoning",
        "sentinel_rasp",
        "sentinel_rasp.core",
        "sentinel_rasp.core.engine",
        "sentinel_rasp.core.monitor",
        "sentinel_rasp.integrations",
        "sentinel_rasp.integrations.fastapi",
        "sentinel_rasp.integrations.flask",
        "sentinel_rasp.integrations.django",
    ]

    for imp in hidden_imports:
        cmd.extend(["--hidden-import", imp])

    cmd.append(str(ROOT_DIR / "launcher.py"))

    print(f"[*] Executing command:\n{' '.join(cmd)}\n")
    res = subprocess.run(cmd, cwd=str(ROOT_DIR))
    if res.returncode == 0:
        print("\n=======================================================")
        print(" [OK] Build completed successfully!")
        print(f" [OK] Executable created at: {ROOT_DIR / 'dist' / 'Shipcheck' / 'Shipcheck.exe'}")
        print("=======================================================\n")
    else:
        print(f"\n[X] Build failed with exit code: {res.returncode}")
        sys.exit(res.returncode)

if __name__ == "__main__":
    build()
