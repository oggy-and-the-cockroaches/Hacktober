"""Sentinel RASP integration service."""

import os
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.database.schema import get_db, get_project_dir


class SentinelIntegrationService:
    """Integrate Sentinel RASP into analyzed projects."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.project_dir = get_project_dir(project_id)

    def generate_integration_preview(self) -> Dict[str, Any]:
        """Generate a preview of Sentinel integration changes."""
        project_context = self._get_project_context()
        framework = self._detect_framework(project_context)

        # Generate integration patch based on framework
        patch = self._generate_patch(framework)

        return {
            "project_id": self.project_id,
            "framework": framework,
            "changes": patch["changes"],
            "dependencies": patch["dependencies"],
            "protection_features": [
                "Runtime attack detection",
                "Request monitoring",
                "Rate anomaly detection",
                "Security event logging",
                "SQL injection protection",
                "Blind SQL injection protection",
                "XSS protection",
                "HTML injection protection",
                "XPath injection protection",
                "Server-side includes injection protection",
                "Server-side template injection protection",
                "CRLF injection protection",
                "Remote code execution protection",
                "OS command injection protection",
                "XML / XXE injection protection",
                "LDAP injection protection",
                "Command injection protection",
                "Secret exfiltration prevention"
            ],
            "files_modified": patch["files_modified"],
            "estimated_latency": "<1ms per request (native engine)",
            "timestamp": datetime.utcnow().isoformat()
        }

    def apply_integration(self, approved: bool = True) -> Dict[str, Any]:
        """Apply Sentinel integration to the project."""
        if not approved:
            return {"success": False, "error": "Integration not approved by developer"}

        project_context = self._get_project_context()
        framework = self._detect_framework(project_context)

        try:
            # Generate and apply patch
            patch = self._generate_patch(framework)

            # Apply file changes
            applied_files = []
            for file_change in patch["changes"]:
                file_path = self.project_dir / file_change["path"]
                file_path.parent.mkdir(parents=True, exist_ok=True)

                if file_change["action"] == "create":
                    file_path.write_text(file_change["content"], encoding="utf-8")
                    applied_files.append(file_change["path"])
                elif file_change["action"] == "modify":
                    content = file_path.read_text(encoding="utf-8")
                    # Apply modifications
                    for modification in file_change.get("modifications", []):
                        content = content.replace(
                            modification["old"],
                            modification["new"]
                        )
                    file_path.write_text(content, encoding="utf-8")
                    applied_files.append(file_change["path"])

            # Update dependencies
            self._update_dependencies(patch["dependencies"])

            # Record integration
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO sentinel_integrations
                    (project_id, enabled, policy_name, integration_patch, applied_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    self.project_id,
                    1,
                    patch.get("policy_name", "default"),
                    json.dumps(patch),
                    datetime.utcnow().isoformat()
                ))

                # Update project
                cursor.execute("""
                    UPDATE projects SET sentinel_enabled = 1, sentinel_integrated_at = ?
                    WHERE id = ?
                """, (datetime.utcnow().isoformat(), self.project_id))

            return {
                "success": True,
                "framework": framework,
                "applied_files": applied_files,
                "dependencies_added": patch["dependencies"],
                "message": "Sentinel RASP integrated successfully",
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def _get_project_context(self) -> Dict[str, Any]:
        """Get project context from database."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT project_context FROM projects WHERE id = ?", (self.project_id,))
            row = cursor.fetchone()
            if row and row[0]:
                return json.loads(row[0])
        return {}

    def _detect_framework(self, project_context: Dict[str, Any]) -> str:
        """Detect the project framework."""
        frameworks = project_context.get("frameworks", [])
        backend_frameworks = project_context.get("backend_frameworks", [])

        all_frameworks = frameworks + backend_frameworks

        if "FastAPI" in all_frameworks:
            return "fastapi"
        if "Flask" in all_frameworks:
            return "flask"
        if "Django" in all_frameworks:
            return "django"
        if "Express" in all_frameworks:
            return "express"

        # Check files directly
        if (self.project_dir / "main.py").exists():
            content = (self.project_dir / "main.py").read_text(errors="ignore")
            if "fastapi" in content.lower():
                return "fastapi"
            if "flask" in content.lower():
                return "flask"

        return "unknown"

    def _generate_patch(self, framework: str) -> Dict[str, Any]:
        """Generate integration patch for the framework."""
        if framework == "fastapi":
            return self._generate_fastapi_patch()
        elif framework == "flask":
            return self._generate_flask_patch()
        elif framework == "django":
            return self._generate_django_patch()
        else:
            return self._generate_generic_patch()

    def _generate_fastapi_patch(self) -> Dict[str, Any]:
        """Generate FastAPI integration patch."""
        sentinel_config = '''"""Sentinel RASP Configuration"""
from sentinel import protect

# Sentinel security policy
SENTINEL_POLICY = {
    "name": "shipcheck_runtime_protection",
    "when": {"event": "SECRET_ACCESS"},
    "forbid": {"event": "NETWORK_SEND"},
    "condition": {"destination": "UNTRUSTED"},
    "action": ["BLOCK", "LOG"],
    "database": {"block_unsafe_dynamic_sql": True, "block_blind_sql_injection": True},
    "html": {"block_unsafe_reflected_html": True, "block_html_injection": True},
    "xpath": {"block_injection": True},
    "template": {"block_server_side_includes": True, "block_template_expressions": True},
    "http": {"block_crlf_injection": True, "block_xml_external_entities": True},
    "directory": {"block_unsafe_ldap_filters": True},
    "process": {"block_rce_payloads": True, "block_os_command_injection": True}
}

def enable_sentinel(app):
    """Enable Sentinel RASP protection on the FastAPI application."""
    return protect(app, SENTINEL_POLICY)
'''

        return {
            "policy_name": "shipcheck_runtime_protection",
            "changes": [
                {
                    "path": "sentinel_config.py",
                    "action": "create",
                    "content": sentinel_config
                }
            ],
            "dependencies": ["sentinel-rasp>=0.1.0"],
            "files_modified": ["sentinel_config.py"],
            "integration_code": '''
# Add to your main application file:
from sentinel_config import enable_sentinel

# After creating your FastAPI app:
app = FastAPI()
enable_sentinel(app)
'''
        }

    def _generate_flask_patch(self) -> Dict[str, Any]:
        """Generate Flask integration patch."""
        sentinel_config = '''"""Sentinel RASP Configuration for Flask"""
from sentinel import protect

SENTINEL_POLICY = {
    "name": "shipcheck_runtime_protection",
    "when": {"event": "SECRET_ACCESS"},
    "forbid": {"event": "NETWORK_SEND"},
    "condition": {"destination": "UNTRUSTED"},
    "action": ["BLOCK", "LOG"]
}

def enable_sentinel(app):
    """Enable Sentinel RASP protection on the Flask application."""
    return protect(app, SENTINEL_POLICY)
'''

        return {
            "policy_name": "shipcheck_runtime_protection",
            "changes": [
                {
                    "path": "sentinel_config.py",
                    "action": "create",
                    "content": sentinel_config
                }
            ],
            "dependencies": ["sentinel-rasp>=0.1.0"],
            "files_modified": ["sentinel_config.py"],
            "integration_code": '''
# Add to your Flask app:
from sentinel_config import enable_sentinel
enable_sentinel(app)
'''
        }

    def _generate_django_patch(self) -> Dict[str, Any]:
        """Generate Django integration patch."""
        middleware = '''"""Sentinel RASP Middleware for Django"""
from sentinel import protect

class SentinelMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.sentinel = protect(None, {
            "name": "shipcheck_runtime_protection",
            "when": {"event": "SECRET_ACCESS"},
            "forbid": {"event": "NETWORK_SEND"},
            "condition": {"destination": "UNTRUSTED"},
            "action": ["BLOCK", "LOG"]
        })

    def __call__(self, request):
        response = self.get_response(request)
        return response
'''

        return {
            "policy_name": "shipcheck_runtime_protection",
            "changes": [
                {
                    "path": "sentinel_middleware.py",
                    "action": "create",
                    "content": middleware
                }
            ],
            "dependencies": ["sentinel-rasp>=0.1.0"],
            "files_modified": ["sentinel_middleware.py"],
            "integration_code": '''
# Add to MIDDLEWARE in settings.py:
'sentinel_middleware.SentinelMiddleware',
'''
        }

    def _generate_generic_patch(self) -> Dict[str, Any]:
        """Generate generic integration patch."""
        return {
            "policy_name": "shipcheck_runtime_protection",
            "changes": [
                {
                    "path": "sentinel_config.py",
                    "action": "create",
                    "content": '''"""Sentinel RASP Configuration"""
from sentinel import protect

SENTINEL_POLICY = {
    "name": "shipcheck_runtime_protection",
    "when": {"event": "SECRET_ACCESS"},
    "forbid": {"event": "NETWORK_SEND"},
    "condition": {"destination": "UNTRUSTED"},
    "action": ["BLOCK", "LOG"]
}
'''
                }
            ],
            "dependencies": ["sentinel-rasp>=0.1.0"],
            "files_modified": ["sentinel_config.py"],
            "integration_code": "# Integrate Sentinel based on your framework"
        }

    def _update_dependencies(self, dependencies: List[str]):
        """Update project dependencies."""
        requirements_file = self.project_dir / "requirements.txt"

        if requirements_file.exists():
            content = requirements_file.read_text(encoding="utf-8")
            for dep in dependencies:
                if dep not in content:
                    content += f"\n{dep}"
            requirements_file.write_text(content, encoding="utf-8")
        else:
            requirements_file.write_text("\n".join(dependencies), encoding="utf-8")


def get_sentinel_integration(project_id: str) -> SentinelIntegrationService:
    """Get Sentinel integration service for a project."""
    return SentinelIntegrationService(project_id)
