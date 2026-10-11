"""Project technology detection service."""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional


class ProjectDetector:
    """Detect project technologies, frameworks, and structure."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.detected = {
            "languages": [],
            "frameworks": [],
            "databases": [],
            "auth_systems": [],
            "deployment": [],
            "package_managers": [],
            "apis": [],
            "frontend_frameworks": [],
            "backend_frameworks": [],
            "project_type": "unknown"
        }

    def detect(self) -> Dict[str, Any]:
        """Run all detection methods and return results."""
        self._detect_languages()
        self._detect_frameworks()
        self._detect_databases()
        self._detect_auth()
        self._detect_deployment()
        self._detect_package_managers()
        self._detect_apis()
        self._detect_project_type()
        return self.detected

    def _detect_languages(self):
        """Detect programming languages from file extensions."""
        extensions = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "JavaScript (React)",
            ".tsx": "TypeScript (React)",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".php": "PHP",
            ".rb": "Ruby",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
            ".kt": "Kotlin",
            ".swift": "Swift",
        }

        found = set()
        for root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__", ".pytest_cache"}]
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in extensions:
                    found.add(extensions[ext])
        self.detected["languages"] = sorted(list(found))

    def _detect_frameworks(self):
        """Detect frameworks from config files and dependencies."""
        frameworks = {
            # Python
            "requirements.txt": ["FastAPI", "Django", "Flask", "Starlette"],
            "pyproject.toml": ["FastAPI", "Django", "Flask", "Poetry"],
            "setup.py": ["FastAPI", "Django", "Flask"],
            "Pipfile": ["FastAPI", "Django", "Flask"],
            # Node.js
            "package.json": ["Express", "Next.js", "React", "Vue", "NestJS", "Fastify", "Koa"],
            # Java
            "pom.xml": ["Spring Boot", "Spring"],
            "build.gradle": ["Spring Boot", "Spring"],
            # Go
            "go.mod": ["Gin", "Echo", "Fiber"],
            # Rust
            "Cargo.toml": ["Actix", "Axum", "Rocket"],
            # PHP
            "composer.json": ["Laravel", "Symfony"],
        }

        for config_file, possible_frameworks in frameworks.items():
            path = self.project_root / config_file
            if path.exists():
                content = path.read_text(errors="ignore").lower()
                for fw in possible_frameworks:
                    if fw.lower() in content:
                        if fw not in self.detected["frameworks"]:
                            self.detected["frameworks"].append(fw)

    def _detect_databases(self):
        """Detect databases from config and code."""
        db_indicators = {
            "postgresql": ["postgresql", "postgres", "psycopg2", "asyncpg", "pg8000"],
            "mysql": ["mysql", "pymysql", "mysqlclient"],
            "sqlite": ["sqlite3", "sqlite"],
            "mongodb": ["mongodb", "pymongo", "motor"],
            "redis": ["redis", "aioredis"],
            "sqlserver": ["sqlserver", "pyodbc", "pymssql"],
            "oracle": ["oracle", "cx_oracle"],
        }

        for db, indicators in db_indicators.items():
            for indicator in indicators:
                # Check config files
                for config in ["requirements.txt", "pyproject.toml", "package.json", "go.mod", "Cargo.toml", "pom.xml", "composer.json"]:
                    path = self.project_root / config
                    if path.exists():
                        content = path.read_text(errors="ignore").lower()
                        if indicator.lower() in content:
                            if db not in self.detected["databases"]:
                                self.detected["databases"].append(db)
                                break
                # Check source code
                for ext in [".py", ".js", ".ts", ".go", ".rs", ".java", ".php"]:
                    for file in self.project_root.rglob(f"*{ext}"):
                        try:
                            content = file.read_text(errors="ignore").lower()
                            if indicator.lower() in content:
                                if db not in self.detected["databases"]:
                                    self.detected["databases"].append(db)
                                break
                        except Exception:
                            continue

    def _detect_auth(self):
        """Detect authentication systems."""
        auth_indicators = {
            "jwt": ["jwt", "jsonwebtoken", "pyjwt", "jose"],
            "oauth": ["oauth", "authlib", "passport"],
            "session": ["session", "express-session", "flask-session"],
            "api_key": ["api_key", "apikey", "api-key"],
            "basic_auth": ["basic_auth", "http_basic"],
            "ldap": ["ldap", "active_directory"],
            "saml": ["saml"],
            "oidc": ["oidc", "openid"],
        }

        for auth, indicators in auth_indicators.items():
            for indicator in indicators:
                for config in ["requirements.txt", "pyproject.toml", "package.json", "go.mod", "Cargo.toml", "pom.xml", "composer.json"]:
                    path = self.project_root / config
                    if path.exists():
                        content = path.read_text(errors="ignore").lower()
                        if indicator.lower() in content:
                            if auth not in self.detected["auth_systems"]:
                                self.detected["auth_systems"].append(auth)
                                break

    def _detect_deployment(self):
        """Detect deployment technologies."""
        deployment_indicators = {
            "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
            "kubernetes": ["kubernetes", "k8s", "helm", "deployment.yaml", "service.yaml"],
            "aws": ["aws", "cloudformation", "serverless.yml", "template.yaml"],
            "gcp": ["gcp", "google-cloud", "app.yaml"],
            "azure": ["azure", "azure-pipelines", "web.config"],
            "vercel": ["vercel.json"],
            "netlify": ["netlify.toml"],
            "heroku": ["Procfile", "app.json"],
            "railway": ["railway.toml"],
            "render": ["render.yaml"],
            "fly": ["fly.toml"],
            "github_actions": [".github/workflows"],
            "gitlab_ci": [".gitlab-ci.yml"],
        }

        for dep, indicators in deployment_indicators.items():
            for indicator in indicators:
                if dep == "github_actions":
                    if (self.project_root / indicator).exists():
                        if dep not in self.detected["deployment"]:
                            self.detected["deployment"].append(dep)
                elif dep == "gitlab_ci":
                    if (self.project_root / indicator).exists():
                        if dep not in self.detected["deployment"]:
                            self.detected["deployment"].append(dep)
                else:
                    for file in self.project_root.rglob(indicator):
                        if file.exists():
                            if dep not in self.detected["deployment"]:
                                self.detected["deployment"].append(dep)
                            break

    def _detect_package_managers(self):
        """Detect package managers."""
        pm_files = {
            "pip": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
            "poetry": ["pyproject.toml", "poetry.lock"],
            "pipenv": ["Pipfile", "Pipfile.lock"],
            "npm": ["package.json", "package-lock.json"],
            "yarn": ["yarn.lock"],
            "pnpm": ["pnpm-lock.yaml"],
            "maven": ["pom.xml"],
            "gradle": ["build.gradle", "build.gradle.kts"],
            "cargo": ["Cargo.toml", "Cargo.lock"],
            "composer": ["composer.json", "composer.lock"],
            "go_mod": ["go.mod", "go.sum"],
        }

        for pm, files in pm_files.items():
            for f in files:
                if (self.project_root / f).exists():
                    if pm not in self.detected["package_managers"]:
                        self.detected["package_managers"].append(pm)
                    break

    def _detect_apis(self):
        """Detect API types."""
        api_indicators = {
            "rest": ["@app.route", "@router.", "fastapi", "express", "flask", "django"],
            "graphql": ["graphql", "apollo", "graphene", "ariadne"],
            "grpc": ["grpc", "protobuf", ".proto"],
            "websocket": ["websocket", "ws://", "wss://"],
        }

        for api, indicators in api_indicators.items():
            for indicator in indicators:
                for ext in [".py", ".js", ".ts", ".go", ".rs", ".java"]:
                    for file in self.project_root.rglob(f"*{ext}"):
                        try:
                            content = file.read_text(errors="ignore").lower()
                            if indicator.lower() in content:
                                if api not in self.detected["apis"]:
                                    self.detected["apis"].append(api)
                                break
                        except Exception:
                            continue

    def _detect_project_type(self):
        """Determine overall project type."""
        if "FastAPI" in self.detected["frameworks"] or "Flask" in self.detected["frameworks"] or "Django" in self.detected["frameworks"]:
            self.detected["backend_frameworks"] = [f for f in self.detected["frameworks"] if f in ["FastAPI", "Flask", "Django", "Starlette", "Express", "NestJS", "Fastify", "Koa", "Spring Boot", "Gin", "Actix", "Laravel", "Symfony"]]
            if "React" in self.detected["frameworks"] or "Vue" in self.detected["frameworks"] or "Next.js" in self.detected["frameworks"]:
                self.detected["project_type"] = "fullstack"
                self.detected["frontend_frameworks"] = [f for f in self.detected["frameworks"] if f in ["React", "Vue", "Next.js"]]
            else:
                self.detected["project_type"] = "backend"
        elif "React" in self.detected["frameworks"] or "Vue" in self.detected["frameworks"] or "Next.js" in self.detected["frameworks"]:
            self.detected["project_type"] = "frontend"
            self.detected["frontend_frameworks"] = [f for f in self.detected["frameworks"] if f in ["React", "Vue", "Next.js"]]
        else:
            self.detected["project_type"] = "other"


def detect_project(project_root: str) -> Dict[str, Any]:
    """Convenience function to detect project technologies."""
    detector = ProjectDetector(project_root)
    return detector.detect()