import os
import sys
import time
import socket
import urllib.request
import threading
from dotenv import load_dotenv


# Ensure backend path is in sys.path
root_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
backend_dir = os.path.join(root_dir, 'backend')

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Load .env file if available
env_path = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.abspath(os.path.dirname(__file__)), '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a local port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def is_shipcheck_server(port: int, host: str = "127.0.0.1") -> bool:
    """Check if an existing service on port is an active Shipcheck instance."""
    try:
        req = urllib.request.Request(f"http://{host}:{port}/api/health", headers={"User-Agent": "ShipcheckLauncher"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def find_available_port(start_port: int = 8000, max_port: int = 8020) -> int:
    """Find the first available port in range."""
    for p in range(start_port, max_port + 1):
        if not is_port_in_use(p):
            return p
    return start_port


def wait_for_server(port: int, timeout: float = 15.0) -> bool:
    """Poll health endpoint until backend is fully initialized."""
    start = time.time()
    url = f"http://127.0.0.1:{port}/api/health"
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ShipcheckLauncher"})
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def start_server(port: int):
    import uvicorn
    from backend.main import app
    print(f"[Shipcheck Launcher] Starting backend on port {port}...")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error", lifespan="off")


if __name__ == "__main__":
    if sys.platform == "win32":
        import io
        if sys.stdout and hasattr(sys.stdout, 'buffer'):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        if sys.stderr and hasattr(sys.stderr, 'buffer'):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    target_port = 8000
    already_running = False

    if is_port_in_use(8000):
        if is_shipcheck_server(8000):
            print("[Shipcheck Launcher] Connected to existing Shipcheck instance on port 8000.")
            already_running = True
        else:
            print("[Shipcheck Launcher] Port 8000 occupied by another service. Selecting next available port...")
            target_port = find_available_port(8001, 8020)

    if not already_running:
        server_thread = threading.Thread(target=start_server, args=(target_port,), daemon=True)
        server_thread.start()
        print(f"[Shipcheck Launcher] Waiting for server readiness on port {target_port}...")
        if not wait_for_server(target_port, timeout=15.0):
            print(f"[Shipcheck Launcher] Warning: Server readiness check timed out on port {target_port}.")
        else:
            print(f"[Shipcheck Launcher] Backend verified responsive on port {target_port}.")

    import webview
    print(f"[Shipcheck Launcher] Initializing desktop GUI window (http://127.0.0.1:{target_port})...")
    window = webview.create_window(
        title="Shipcheck / Sentinel - Security Command Center",
        url=f"http://127.0.0.1:{target_port}",
        width=1320,
        height=880,
        min_size=(900, 600),
        resizable=True
    )
    webview.start()
