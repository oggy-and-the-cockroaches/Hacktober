"""Shipcheck Application Launcher & Desktop Runner.

Starts FastAPI on port 8000, launches Chrome/browser, and stays running in the terminal.
"""

import os
import sys
import time
import socket
import threading
import webbrowser
import subprocess
import uvicorn

# Multiprocessing support for PyInstaller frozen binaries
import multiprocessing
multiprocessing.freeze_support()

# Ensure application root directory is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import the FastAPI application
from backend.main import app


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is already listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def open_browser_when_ready(url: str, port: int, host: str = "127.0.0.1"):
    """Wait until the server is listening, then open Chrome or default browser."""
    # Poll for port to become active (up to 15 seconds)
    start_time = time.time()
    while time.time() - start_time < 15:
        if is_port_in_use(port, host):
            time.sleep(0.4)  # Small stabilization delay
            break
        time.sleep(0.2)

    # Attempt to open in Google Chrome specifically on Windows, falling back to default browser
    opened = False
    if sys.platform == "win32":
        chrome_paths = [
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
        for chrome_path in chrome_paths:
            if os.path.exists(chrome_path):
                try:
                    subprocess.Popen([chrome_path, url])
                    opened = True
                    break
                except Exception:
                    pass

    if not opened:
        try:
            webbrowser.open(url)
        except Exception as e:
            print(f"[*] Notice: Navigate your browser to: {url} ({e})")


def print_banner(host: str, port: int):
    """Print a clean CLI banner."""
    print("""
========================================================================
   ____ _     _             _               _    
  / ___| |__ (_)_ __   ___| |__   ___  ___| | __
  \\___ \\| '_ \\| | '_ \\ / __| '_ \\ / _ \\/ __| |/ /
   ___) | | | | | |_) | (__| | | |  __/ (__|   < 
  |____/|_| |_|_| .__/ \\___|_| |_|\\___|\\___|_|\\_\\
                |_|                              
   Pre-deployment Security & Sentinel RASP Platform
========================================================================
""")
    print(f"   ⚡ Shipcheck Server active on: http://{host}:{port}")
    print(f"   🌐 Opening dashboard in browser (Chrome)...")
    print(f"   🛑 To stop the server, press CTRL+C in this terminal.")
    print("========================================================================\n")


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    url = f"http://{host}:{port}"

    print_banner(host, port)

    # Start browser opener in background thread
    browser_thread = threading.Thread(
        target=open_browser_when_ready,
        args=(url, port, host),
        daemon=True
    )
    browser_thread.start()

    # Run Uvicorn server in the foreground terminal thread
    try:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n[!] Stopping Shipcheck server...")
    except Exception as e:
        print(f"\n[X] Server error: {e}")


if __name__ == "__main__":
    main()
