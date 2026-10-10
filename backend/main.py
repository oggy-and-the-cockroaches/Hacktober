"""Main FastAPI application for Shipcheck + Sentinel platform."""

import os
import sys

# Ensure project root is in sys.path for backend.* imports when run as script
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database.schema import init_db
from backend.api import projects, scans, reports, sandbox, fixes, sentinel, runtime, proxy, remediation

# Initialize database synchronously before app creation
init_db()
print("Database initialized")

# Create projects directory
projects_dir = os.environ.get("SHIPCHECK_PROJECTS_DIR", "./projects")
os.makedirs(projects_dir, exist_ok=True)

app = FastAPI(
    title="Shipcheck + Verified Remediation Engine",
    description="Pre-deployment security intelligence (Shipcheck) + Gemma Remediation Engine + Sentinel RASP",
    version="2.0.0",
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(remediation.router)
app.include_router(sandbox.router)
app.include_router(fixes.router)
app.include_router(sentinel.router)
app.include_router(runtime.router)
app.include_router(proxy.router)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "shipcheck-sentinel",
        "version": "2.0.0"
    }


@app.get("/api/version")
async def version():
    """Version endpoint."""
    return {
        "version": "2.0.0",
        "name": "Shipcheck + Sentinel",
        "components": {
            "shipcheck": "Pre-deployment security platform",
            "sentinel": "Runtime RASP protection"
        }
    }


# Serve frontend static files
if getattr(sys, "frozen", False):
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
    frontend_dir = os.path.join(base_dir, "frontend")
else:
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_frontend():
        """Serve the frontend index.html."""
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Frontend not found."}

    @app.get("/{path:path}")
    async def serve_frontend_paths(path: str):
        """Serve frontend for client-side routing."""
        # Don't intercept API routes
        if path.startswith("api/") or path == "health" or path.startswith("projects/") or path.startswith("scans/") or path.startswith("reports/") or path.startswith("remediation/") or path.startswith("sandbox/") or path.startswith("fixes/") or path.startswith("sentinel/") or path.startswith("runtime/"):
            raise HTTPException(status_code=404, detail="Not found")

        file_path = os.path.join(frontend_dir, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)

        # Fallback to index.html for SPA routing
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)

        return {"message": "Not found"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
