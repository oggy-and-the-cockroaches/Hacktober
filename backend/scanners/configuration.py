"""Configuration scanner for detecting insecure configurations."""

import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from .base import BaseScanner, Finding


class ConfigurationScanner(BaseScanner):
    """Scan for configuration security issues."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        super().__init__(project_root, project_context)
        self.category = "configuration"

    def scan(self) -> List[Finding]:
        """Run all configuration checks."""
        self._check_config_files()
        self._check_cors_in_source_files()
        self._check_env_files()
        self._check_docker_security()
        self._check_gitignore()
        self._check_secrets_in_config()
        self._check_insecure_headers()
        self._check_debug_configs()
        return self.findings

    def _redact_secret(self, value: str) -> str:
        """Redact sensitive values in evidence."""
        if len(value) <= 8:
            return "[REDACTED]"
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def _get_line_number(self, content: str, match: re.Match) -> int:
        """Get line number for a regex match."""
        return content[:match.start()].count('\n') + 1

    def _add_config_finding(
        self,
        severity: str,
        title: str,
        description: str,
        file_path: str,
        line_number: Optional[int],
        evidence: str,
        confidence: str,
        recommendation: str,
        config_type: str = "",
        existing_solution: str = "",
        project_specific_solution: str = "",
    ):
        """Add a finding with all extended fields populated."""
        finding = Finding(
            category=self.category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            file_path=file_path,
            line_number=line_number,
            confidence=confidence,
            recommendation=recommendation,
            metadata={"config_type": config_type, "detection_source": "CONFIGURATION"},
            suggested_fix=recommendation,
            existing_solution=existing_solution or self._get_existing_solution(config_type),
            project_specific_solution=project_specific_solution or f"Fix in {file_path}: {recommendation}",
            detection_source="CONFIGURATION",
        )
        self._add_finding(finding)

    def _get_existing_solution(self, config_type: str) -> str:
        """Get existing solution for a config type."""
        solutions = {
            "debug": "Use environment-specific configuration files. Set DEBUG=False in production. Use separate config files for dev/staging/prod.",
            "cors": "Restrict CORS to specific trusted origins. Never use wildcard (*) with credentials. Configure explicit allowed origins, methods, and headers.",
            "ssl": "Enable SSL/TLS verification in production. Use proper certificate validation. For self-signed certs in dev, use separate config.",
            "docker_root": "Add 'USER <non-root-user>' to Dockerfile. Create a dedicated user with minimal privileges. Use multi-stage builds.",
            "docker_latest": "Pin base image to a specific version tag (e.g., FROM python:3.11-slim) for reproducible builds.",
            "docker_secrets": "Never copy secret files into Docker images. Use build secrets (--mount=type=secret) or runtime secret injection.",
            "gitignore": "Create .gitignore with entries for .env, __pycache__, node_modules, *.db, dist/, build/, .venv, *.log.",
            "secrets": "Move secrets to environment variables or secret manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Rotate exposed credentials.",
            "headers": "Configure security headers: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy, Strict-Transport-Security, Referrer-Policy.",
            "cookies": "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on cookies. Use __Host- prefix for session cookies.",
            "production": "Use production-specific configuration. Disable debug, enable security features, configure proper logging levels.",
            "defaults": "Change default credentials immediately. Use strong, unique passwords. Disable default admin accounts.",
            "endpoints": "Restrict admin/debug endpoints with authentication. Use IP whitelisting or VPN access. Disable in production.",
        }
        return solutions.get(config_type, "Follow security best practices for configuration management.")

    def _check_config_files(self):
        """Check configuration files for insecure settings."""
        config_files = [
            "config.json", "config.yaml", "config.yml", "settings.json",
            "settings.py", "config.py", "application.properties",
            "application.yml", "application.yaml", "appsettings.json",
            "web.config", "fastapi.json", "uvicorn.json", "gunicorn.conf.py",
            "celeryconfig.py", "alembic.ini", "pytest.ini", "tox.ini",
        ]

        for config_file in config_files:
            path = self.project_root / config_file
            if not path.exists():
                continue

            content = self._read_file(path)
            if not content:
                continue

            # Check for debug mode
            for match in re.finditer(r'(?i)["\']?debug["\']?\s*[:=]\s*true', content):
                line_num = self._get_line_number(content, match)
                self._add_config_finding(
                    severity="high",
                    title=f"Debug Mode Enabled in {config_file}",
                    description="Debug mode is enabled in configuration. This exposes stack traces, internal paths, and sensitive data in error responses.",
                    file_path=config_file,
                    line_number=line_num,
                    evidence=f"{config_file}:{line_num}: debug=true (detected)",
                    confidence="high",
                    recommendation="Set debug=false in production configuration. Use environment-specific config files.",
                    config_type="debug",
                    project_specific_solution=f"In {config_file} line {line_num}, change debug=true to debug=false or use environment variable.",
                )

            # Check for insecure CORS
            # Match both: allow_origins="*" and allow_origins=["*"]
            cors_patterns = [
                r'(?i)(allow_origins|cors|allowed_origins)\s*[:=]\s*["\']\*["\']',  # string wildcard
                r'(?i)(allow_origins|cors|allowed_origins)\s*[:=]\s*\[\s*["\']\*["\']\s*\]',  # list wildcard
            ]
            for cors_pattern in cors_patterns:
                for match in re.finditer(cors_pattern, content):
                    line_num = self._get_line_number(content, match)
                    self._add_config_finding(
                        severity="medium",
                        title=f"Wildcard CORS in {config_file}",
                        description="CORS is configured to allow all origins (*), which can expose APIs to cross-origin attacks.",
                        file_path=config_file,
                        line_number=line_num,
                        evidence=f"{config_file}:{line_num}: allow_origins=* (detected)",
                        confidence="high",
                        recommendation="Restrict CORS to specific trusted origins. Avoid wildcard (*) with credentials.",
                        config_type="cors",
                        project_specific_solution=f"In {config_file} line {line_num}, replace '*' with a list of trusted origins.",
                    )

            # Check for insecure SSL
            for match in re.finditer(r'(?i)["\']?(ssl_verify|verify_ssl|tls_verify|verify_cert)["\']?\s*[:=]\s*false', content):
                line_num = self._get_line_number(content, match)
                self._add_config_finding(
                    severity="high",
                    title=f"SSL Verification Disabled in {config_file}",
                    description="SSL/TLS certificate verification is disabled, enabling man-in-the-middle attacks.",
                    file_path=config_file,
                    line_number=line_num,
                    evidence=f"{config_file}:{line_num}: ssl_verify=false (detected)",
                    confidence="high",
                    recommendation="Enable SSL verification in production. Use proper certificate validation.",
                    config_type="ssl",
                    project_specific_solution=f"In {config_file} line {line_num}, change ssl_verify=false to ssl_verify=true.",
                )

    def _check_cors_in_source_files(self):
        """Check for CORS misconfiguration in source files (e.g., middleware setup)."""
        cors_patterns = [
            r'(?i)(allow_origins|cors|allowed_origins)\s*[:=]\s*["\']\*["\']',
            r'(?i)(allow_origins|cors|allowed_origins)\s*[:=]\s*\[\s*["\']\*["\']\s*\]',
        ]
        # Scan common files where CORS is configured in code
        for file_path in self._get_source_files([".py", ".js", ".ts", ".go", ".java", ".rs"]):
            content = self._read_file(file_path)
            if not content:
                continue
            for cors_pattern in cors_patterns:
                for match in re.finditer(cors_pattern, content):
                    line_num = self._get_line_number(content, match)
                    self._add_config_finding(
                        severity="medium",
                        title=f"Wildcard CORS in {file_path.name}",
                        description="CORS is configured to allow all origins (*) in application code, which can expose APIs to cross-origin attacks.",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        evidence=f"{file_path.name}:{line_num}: allow_origins=* (detected)",
                        confidence="high",
                        recommendation="Restrict CORS to specific trusted origins. Avoid wildcard (*) with credentials.",
                        config_type="cors",
                        project_specific_solution=f"In {file_path.name} line {line_num}, replace '*' with a list of trusted origins.",
                    )

    def _check_env_files(self):
        """Check .env files for exposed secrets."""
        env_files = [".env", ".env.local", ".env.production", ".env.staging", ".env.development", ".env.test"]

        for env_file in env_files:
            path = self.project_root / env_file
            if not path.exists():
                continue

            content = self._read_file(path)
            if not content:
                continue

            secret_patterns = [
                (r'(?i)(aws[_-]?access[_-]?key|aws_access_key_id)\s*=\s*["\']?([A-Z0-9]{20})["\']?', "AWS Access Key"),
                (r'(?i)(aws[_-]?secret[_-]?key|aws_secret_access_key)\s*=\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "AWS Secret Key"),
                (r'(?i)(api[_-]?key|apikey)\s*=\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "API Key"),
                (r'(?i)(secret|secret[_-]?key)\s*=\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Secret Key"),
                (r'(?i)(password|passwd|secret)\s*=\s*["\']?([^"\'\s]{8,})["\']?', "Password"),
                (r'(?i)(token|auth[_-]?token)\s*=\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Token"),
                (r'(?i)(private[_-]?key)\s*=\s*["\']?([^"\']{20,})["\']?', "Private Key"),
            ]

            for pattern, secret_type in secret_patterns:
                for match in re.finditer(pattern, content):
                    value = match.group(2) if len(match.groups()) > 1 else match.group(1)
                    
                    # Skip obvious placeholders for non-AWS keys
                    is_aws_key = "AWS" in secret_type
                    if not is_aws_key and value.lower() in ("your_key_here", "changeme", "xxx", "placeholder", "your_api_key_here", "your-secret-here", "change_me", "test", "example", "dummy", "fake", "mock", "sample", "invalid", "xxxxxxxx", "00000000", "12345678", "abcdefgh"):
                        continue
                    
                    # Skip if line looks like a test/example/comment (but not for AWS keys which have specific patterns)
                    if not is_aws_key:
                        line_start = content.rfind('\n', 0, match.start()) + 1
                        line_end = content.find('\n', match.start())
                        if line_end == -1:
                            line_end = len(content)
                        line = content[line_start:line_end].strip()
                        if line.startswith(('#', '//', '/*', '*', '--', ';', 'REM')):
                            continue
                        if any(kw in line.lower() for kw in ['test', 'example', 'sample', 'dummy', 'mock', 'fake', 'placeholder', 'todo', 'fixme']):
                            continue

                    line_num = self._get_line_number(content, match)
                    redacted = self._redact_secret(value)
                    self._add_config_finding(
                        severity="critical",
                        title=f"Secret Exposed in {env_file}: {secret_type}",
                        description=f"A {secret_type} is stored in {env_file} which may be committed to version control.",
                        file_path=env_file,
                        line_number=line_num,
                        evidence=f"{env_file}:{line_num}: {secret_type}={redacted}",
                        confidence="high",
                        recommendation=f"Remove the {secret_type} from {env_file}. Use environment variables or a secret manager. Rotate the exposed credential immediately.",
                        config_type="secrets",
                        project_specific_solution=f"In {env_file} line {line_num}, remove the {secret_type} and set it as an environment variable at runtime.",
                    )

    def _check_docker_security(self):
        """Check Dockerfile for security issues."""
        dockerfile = self.project_root / "Dockerfile"
        if not dockerfile.exists():
            return

        content = self._read_file(dockerfile)
        if not content:
            return

        # Check for root user
        user_matches = list(re.finditer(r'(?i)^USER\s+(\w+)', content, re.MULTILINE))
        if "USER root" in content:
            self._add_config_finding(
                severity="medium",
                title="Docker Container Runs as Root (USER root)",
                description="The Dockerfile explicitly sets USER root, giving the container elevated privileges.",
                file_path="Dockerfile",
                line_number=None,
                evidence="Dockerfile: USER root",
                confidence="high",
                recommendation="Remove 'USER root' and add 'USER <non-root-user>' to Dockerfile. Create a dedicated user with minimal privileges.",
                config_type="docker_root",
            )
        elif not user_matches:
            # Check if base image is known to run as non-root by default
            from_match = re.search(r'(?i)^FROM\s+(\S+)', content, re.MULTILINE)
            base_image = from_match.group(1) if from_match else "unknown"
            # Only distroless/chainguard/busybox images typically run as non-root by default.
            # Standard python/node/ubuntu/debian/alpine images run as root unless USER is set.
            non_root_bases = {"distroless", "gcr.io/distroless", "chainguard", "busybox"}
            is_known_non_root = any(base in base_image.lower() for base in non_root_bases)
            
            self._add_config_finding(
                severity="low" if is_known_non_root else "medium",
                title="Docker Container May Run as Root (No USER Directive)",
                description=f"The Dockerfile does not specify a USER directive. Base image '{base_image}' {'typically runs as non-root' if is_known_non_root else 'runs as root by default'}. Explicit USER is recommended for defense-in-depth.",
                file_path="Dockerfile",
                line_number=None,
                evidence=f"Dockerfile: No USER directive (FROM {base_image})",
                confidence="medium" if is_known_non_root else "high",
                recommendation="Add 'USER <non-root-user>' to Dockerfile for explicit non-root execution. Create a dedicated user with minimal privileges.",
                config_type="docker_root",
            )

        # Check for latest tag
        for match in re.finditer(r'(?i)FROM\s+\S+:latest', content):
            line_num = self._get_line_number(content, match)
            self._add_config_finding(
                severity="low",
                title="Docker Image Uses 'latest' Tag",
                description="Using 'latest' tag makes builds non-reproducible and may introduce unexpected changes.",
                file_path="Dockerfile",
                line_number=line_num,
                evidence=f"Dockerfile:{line_num}: FROM image:latest",
                confidence="high",
                recommendation="Pin base image to a specific version tag for reproducible builds.",
                config_type="docker_latest",
            )

        # Check for secrets in Dockerfile
        for match in re.finditer(r'(?i)(ADD|COPY)\s+.*\.(env|pem|key|secret)', content):
            line_num = self._get_line_number(content, match)
            self._add_config_finding(
                severity="critical",
                title="Potential Secret Copied into Docker Image",
                description="The Dockerfile copies secret files into the image, exposing them in the final artifact.",
                file_path="Dockerfile",
                line_number=line_num,
                evidence=f"Dockerfile:{line_num}: ADD/COPY of secret file",
                confidence="high",
                recommendation="Never copy secret files into Docker images. Use build secrets or runtime secret injection.",
                config_type="docker_secrets",
            )

    def _check_gitignore(self):
        """Check .gitignore for missing entries."""
        gitignore = self.project_root / ".gitignore"
        if not gitignore.exists():
            self._add_config_finding(
                severity="medium",
                title="Missing .gitignore File",
                description="No .gitignore file found. This risks committing sensitive files, build artifacts, and dependencies.",
                file_path=None,
                line_number=None,
                evidence="No .gitignore in project root",
                confidence="high",
                recommendation="Create a .gitignore file. Include: .env, __pycache__, node_modules, *.db, dist/, build/",
                config_type="gitignore",
            )
            return

        content = self._read_file(gitignore)
        if not content:
            return

        required_entries = [".env", "__pycache__", "*.pyc", "node_modules"]
        missing = [e for e in required_entries if e not in content]

        if missing:
            self._add_config_finding(
                severity="low",
                title=".gitignore Missing Entries",
                description=f"The .gitignore file is missing common entries: {', '.join(missing)}",
                file_path=".gitignore",
                line_number=None,
                evidence=f".gitignore missing: {', '.join(missing)}",
                confidence="medium",
                recommendation=f"Add these entries to .gitignore: {', '.join(missing)}",
                config_type="gitignore",
            )

    def _check_secrets_in_config(self):
        """Check for secrets in configuration files."""
        config_patterns = [
            (r'(?i)["\']?(password|passwd)["\']?\s*[:=]\s*["\']?([^"\'\s,]{8,})["\']?', "Password"),
            (r'(?i)["\']?(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "API Key"),
            (r'(?i)["\']?(secret|secret[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Secret"),
            (r'(?i)["\']?(token|auth[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Token"),
        ]

        for file_path in self._get_source_files([".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, secret_type in config_patterns:
                for match in re.finditer(pattern, content):
                    value = match.group(2) if len(match.groups()) > 1 else match.group(1)
                    if value.lower() in ("your_key_here", "changeme", "xxx", "placeholder", "test", "example", "dummy", "fake", "mock", "sample", "invalid", "xxxxxxxx", "00000000", "12345678", "abcdefgh"):
                        continue
                    # Skip if line looks like a test/example/comment
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line = content[line_start:content.find('\n', match.start())].strip()
                    if line.startswith(('#', '//', '/*', '*', '--', ';', 'REM')):
                        continue
                    if any(kw in line.lower() for kw in ['test', 'example', 'sample', 'dummy', 'mock', 'fake', 'placeholder', 'todo', 'fixme']):
                        continue

                    line_num = self._get_line_number(content, match)
                    redacted = self._redact_secret(value)
                    self._add_config_finding(
                        severity="critical",
                        title=f"Hardcoded {secret_type} in Configuration",
                        description=f"A {secret_type} is hardcoded in a configuration file.",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        evidence=f"{file_path.name}:{line_num}: {secret_type}={redacted}",
                        confidence="high",
                        recommendation=f"Move the {secret_type} to environment variables or a secret manager.",
                        config_type="secrets",
                        project_specific_solution=f"In {file_path.name} line {line_num}, remove the {secret_type} and use environment variable.",
                    )

    def _check_insecure_headers(self):
        """Check for missing security headers configuration."""
        files_with_middleware = []
        
        # Security header patterns (support both dash and underscore variants)
        security_header_patterns = [
            r"X[-_]Content[-_]Type[-_]Options",
            r"X[-_]Frame[-_]Options",
            r"Content[-_]Security[-_]Policy",
            r"Strict[-_]Transport[-_]Security",
            r"X[-_]XSS[-_]Protection",
            r"Referrer[-_]Policy",
        ]
        
        for file_path in self._get_source_files([".py", ".js", ".ts", ".conf", ".yaml", ".yml"]):
            content = self._read_file(file_path)
            if not content:
                continue

            # Check for security headers middleware
            has_security_headers = any(re.search(p, content, re.IGNORECASE) for p in security_header_patterns)

            has_middleware = "middleware" in content.lower() or "headers" in content.lower()
            
            if has_middleware:
                files_with_middleware.append((file_path, has_security_headers))

        # Report findings for middleware files lacking security headers
        for file_path, has_security_headers in files_with_middleware:
            if not has_security_headers:
                self._add_config_finding(
                    severity="medium",
                    title="Security Headers Not Configured",
                    description="No security headers configuration detected. Missing headers expose the application to XSS, clickjacking, and MIME sniffing attacks.",
                    file_path=str(file_path.relative_to(self.project_root)),
                    line_number=None,
                    evidence=f"No security headers found in {file_path.name}",
                    confidence="medium",
                    recommendation="Configure security headers: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy, Strict-Transport-Security, Referrer-Policy.",
                    config_type="headers",
                )

    def _check_debug_configs(self):
        """Check for debug configurations."""
        debug_patterns = [
            (r'(?i)DEBUG\s*=\s*True', "DEBUG=True"),
            (r'(?i)debug\s*:\s*true', "debug: true"),
            (r'(?i)"debug"\s*:\s*true', '"debug": true'),
            (r'(?i)NODE_ENV\s*=\s*["\']development["\']', "NODE_ENV=development"),
            (r'(?i)APP_ENV\s*=\s*["\']dev["\']', "APP_ENV=dev"),
        ]

        # Only scan configuration and source files, not all files
        config_extensions = [".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties"]
        for file_path in self._get_source_files(config_extensions):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in debug_patterns:
                for match in re.finditer(pattern, content):
                    line_num = self._get_line_number(content, match)
                    self._add_config_finding(
                        severity="high",
                        title=f"Debug Configuration: {desc}",
                        description=f"Debug/development configuration detected: {desc}. This exposes sensitive information in production.",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        evidence=f"Line {line_num}: {desc}",
                        confidence="high",
                        recommendation="Use environment-specific configuration. Set DEBUG=False and NODE_ENV=production for production deployments.",
                        config_type="debug",
                        project_specific_solution=f"In {file_path.name} line {line_num}, change {desc} to production value.",
                    )