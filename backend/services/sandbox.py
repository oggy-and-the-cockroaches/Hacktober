"""Secure sandbox execution service for untrusted projects."""

import os
import json
import uuid
import asyncio
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


class SandboxService:
    """Execute projects in an isolated sandbox environment."""

    def __init__(self, project_root: str, project_id: str):
        self.project_root = Path(project_root)
        self.project_id = project_id
        self.execution_id = str(uuid.uuid4())
        self.container_id: Optional[str] = None
        self.port: Optional[int] = None
        self.temp_dir: Optional[Path] = None

    async def execute(self, timeout: int = 120) -> Dict[str, Any]:
        """Execute the project in a sandbox and return results."""
        result = {
            "execution_id": self.execution_id,
            "project_id": self.project_id,
            "status": "pending",
            "started_at": datetime.utcnow().isoformat(),
            "checks": [],
            "error": None,
        }

        try:
            # Step 1: Detect project type
            project_type = self._detect_project_type()
            result["project_type"] = project_type

            # Step 2: Try Docker-based execution if available
            docker_available = await self._check_docker_available()
            if docker_available:
                result["checks"].append({"check": "docker_available", "status": "passed"})
                execution = await self._execute_docker(timeout)
            else:
                result["checks"].append({"check": "docker_available", "status": "skipped", "reason": "Docker not available"})
                execution = await self._execute_local(timeout)

            result.update(execution)
            result["status"] = "completed"

        except asyncio.TimeoutError:
            result["status"] = "timeout"
            result["error"] = f"Execution timed out after {timeout} seconds"
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
        finally:
            await self.cleanup()

        result["completed_at"] = datetime.utcnow().isoformat()
        return result

    def _detect_project_type(self) -> str:
        """Detect the project type for execution."""
        if (self.project_root / "package.json").exists():
            return "node"
        if (self.project_root / "requirements.txt").exists() or (self.project_root / "pyproject.toml").exists():
            return "python"
        if (self.project_root / "go.mod").exists():
            return "go"
        if (self.project_root / "pom.xml").exists():
            return "java"
        if (self.project_root / "Dockerfile").exists():
            return "docker"
        return "unknown"

    async def _check_docker_available(self) -> bool:
        """Check if Docker is available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.wait(), timeout=10)
            return proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError):
            return False

    async def _execute_docker(self, timeout: int) -> Dict[str, Any]:
        """Execute project using Docker."""
        result = {"method": "docker", "checks": []}

        # Build image
        image_tag = f"shipcheck-sandbox-{self.execution_id[:8]}"
        try:
            build_proc = await asyncio.create_subprocess_exec(
                "docker", "build", "-t", image_tag, str(self.project_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(build_proc.communicate(), timeout=120)

            if build_proc.returncode != 0:
                result["build_error"] = stderr.decode()[:500]
                result["checks"].append({"check": "build", "status": "failed"})
                return result

            result["checks"].append({"check": "build", "status": "passed"})

            # Run container with security constraints
            self.port = self._find_free_port()
            run_proc = await asyncio.create_subprocess_exec(
                "docker", "run", "-d",
                "--memory=512m",
                "--cpus=1",
                "--pids-limit=100",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--network=none",
                "-p", f"{self.port}:80",
                image_tag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(run_proc.communicate(), timeout=30)

            if run_proc.returncode != 0:
                result["run_error"] = stderr.decode()[:500]
                result["checks"].append({"check": "run", "status": "failed"})
                return result

            self.container_id = stdout.decode().strip()
            result["container_id"] = self.container_id
            result["port"] = self.port
            result["checks"].append({"check": "run", "status": "passed"})

            # Wait for startup
            await asyncio.sleep(3)

            # Run dynamic checks
            dynamic_results = await self._run_dynamic_checks(f"http://localhost:{self.port}")
            result["checks"].extend(dynamic_results)

        except asyncio.TimeoutError:
            result["checks"].append({"check": "execution", "status": "timeout"})
        finally:
            # Cleanup container
            if self.container_id:
                try:
                    await asyncio.create_subprocess_exec(
                        "docker", "stop", self.container_id,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await asyncio.create_subprocess_exec(
                        "docker", "rm", self.container_id,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                except Exception:
                    pass

        return result

    async def _execute_local(self, timeout: int) -> Dict[str, Any]:
        """Execute project locally with limited isolation (fallback)."""
        result = {"method": "local", "checks": []}

        project_type = self._detect_project_type()

        if project_type == "python":
            # Try to find and run main entry point
            entry_points = ["main.py", "app.py", "run.py", "server.py"]
            entry = None
            for ep in entry_points:
                if (self.project_root / ep).exists():
                    entry = ep
                    break

            if entry:
                result["checks"].append({"check": "entry_point", "status": "passed", "entry": entry})
                # Note: We don't actually execute untrusted code locally
                # This is a safety measure - only Docker execution is allowed
                result["checks"].append({
                    "check": "execution",
                    "status": "skipped",
                    "reason": "Local execution disabled for security. Use Docker for sandbox execution."
                })
            else:
                result["checks"].append({"check": "entry_point", "status": "failed", "reason": "No entry point found"})

        elif project_type == "node":
            if (self.project_root / "package.json").exists():
                result["checks"].append({"check": "entry_point", "status": "passed", "entry": "package.json"})
                result["checks"].append({
                    "check": "execution",
                    "status": "skipped",
                    "reason": "Local execution disabled for security. Use Docker for sandbox execution."
                })
            else:
                result["checks"].append({"check": "entry_point", "status": "failed"})

        else:
            result["checks"].append({
                "check": "execution",
                "status": "skipped",
                "reason": f"Unsupported project type: {project_type}"
            })

        return result

    async def _run_dynamic_checks(self, base_url: str) -> List[Dict[str, Any]]:
        """Run dynamic security checks against the running application."""
        checks = []

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Check 404 behavior
                try:
                    resp = await client.get(f"{base_url}/nonexistent-route-12345")
                    if resp.status_code == 404:
                        checks.append({"check": "404_handling", "status": "passed"})
                    else:
                        checks.append({"check": "404_handling", "status": "warning", "detail": f"Got {resp.status_code}"})
                except Exception:
                    checks.append({"check": "404_handling", "status": "failed"})

                # Check security headers
                try:
                    resp = await client.get(base_url)
                    headers = resp.headers
                    security_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
                    missing = [h for h in security_headers if h not in headers]
                    if missing:
                        checks.append({"check": "security_headers", "status": "warning", "missing": missing})
                    else:
                        checks.append({"check": "security_headers", "status": "passed"})
                except Exception:
                    checks.append({"check": "security_headers", "status": "failed"})

                # Check for exposed sensitive endpoints
                sensitive_paths = ["/admin", "/debug", "/.env", "/config", "/backup"]
                exposed = []
                for path in sensitive_paths:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code == 200:
                            exposed.append(path)
                    except Exception:
                        pass

                if exposed:
                    checks.append({"check": "exposed_endpoints", "status": "warning", "exposed": exposed})
                else:
                    checks.append({"check": "exposed_endpoints", "status": "passed"})

        except ImportError:
            checks.append({"check": "dynamic", "status": "skipped", "reason": "httpx not available"})

        return checks

    def _find_free_port(self) -> int:
        """Find a free port for the container."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    async def cleanup(self):
        """Clean up sandbox resources."""
        if self.container_id:
            try:
                await asyncio.create_subprocess_exec(
                    "docker", "stop", self.container_id,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await asyncio.create_subprocess_exec(
                    "docker", "rm", self.container_id,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
            except Exception:
                pass

        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)


async def run_sandbox(project_root: str, project_id: str, timeout: int = 120) -> Dict[str, Any]:
    """Run a project in the sandbox."""
    service = SandboxService(project_root, project_id)
    return await service.execute(timeout)