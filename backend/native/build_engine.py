"""Build Shipcheck's optional native inspector with g++ or clang++."""

import os
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).parent
compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("No g++ or clang++ compiler found. Shipcheck will use the Python fallback.")
suffix = ".dll" if os.name == "nt" else ".so"
output = root / f"shipcheck_inspector_v1{suffix}"
subprocess.run([compiler, "-O3", "-std=c++17", "-shared", "-o", str(output), str(root / "shipcheck_inspector.cpp")], check=True)
print(f"Built {output}")
