from pathlib import Path
import subprocess
def build(output: Path):
    root = Path(__file__).resolve().parents[2]
    output.parent.mkdir(parents=True, exist_ok=True)
    command = ["g++", "-std=c++17", "-shared", "-static", "-static-libstdc++", "-static-libgcc", "-O2", "-I", str(root / "core/cpp/include"),
               str(root / "core/cpp/src/engine.cpp"), str(root / "core/cpp/src/bridge.cpp"), "-o", str(output)]
    subprocess.run(command, check=True)
