"""Dependency scanner for detecting vulnerable dependencies."""

import re
import json
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, Finding


# Known vulnerable package patterns (simplified CVE database)
KNOWN_VULNERABILITIES = {
    "python": {
        "django": [
            {"version": "<2.2.28", "cve": "CVE-2021-33571", "severity": "high", "description": "Potential SQL injection in QuerySet.values()"},
            {"version": "<3.2.13", "cve": "CVE-2022-28346", "severity": "high", "description": "Potential SQL injection in QuerySet.values()"},
        ],
        "flask": [
            {"version": "<2.2.5", "cve": "CVE-2023-30861", "severity": "high", "description": "Possible disclosure of permanent session cookie due to missing Vary: Cookie header"},
        ],
        "requests": [
            {"version": "<2.31.0", "cve": "CVE-2023-32681", "severity": "medium", "description": "Proxy-Authorization header leak on redirect"},
        ],
        "pyyaml": [
            {"version": "<5.4", "cve": "CVE-2020-14343", "severity": "critical", "description": "Arbitrary code execution via unsafe yaml.load"},
        ],
        "jinja2": [
            {"version": "<2.11.3", "cve": "CVE-2020-28493", "severity": "medium", "description": "ReDoS in urlize filter"},
        ],
        "urllib3": [
            {"version": "<1.26.5", "cve": "CVE-2021-33503", "severity": "high", "description": "Catastrophic backtracking in URL parsing"},
        ],
        "cryptography": [
            {"version": "<3.4.8", "cve": "CVE-2023-23931", "severity": "medium", "description": "Cipher.update_into can corrupt memory"},
        ],
        "pillow": [
            {"version": "<9.0.1", "cve": "CVE-2022-22817", "severity": "critical", "description": "Arbitrary code execution via eval in ImageMath"},
        ],
    },
    "node": {
        "express": [
            {"version": "<4.17.3", "cve": "CVE-2022-24999", "severity": "high", "description": "qs library prototype pollution"},
        ],
        "lodash": [
            {"version": "<4.17.21", "cve": "CVE-2021-23337", "severity": "high", "description": "Command injection in template"},
        ],
        "axios": [
            {"version": "<0.21.2", "cve": "CVE-2021-3749", "severity": "medium", "description": "ReDoS in axios"},
        ],
    },
}


class DependencyScanner(BaseScanner):
    """Scan for vulnerable dependencies."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        super().__init__(project_root, project_context)
        self.category = "dependency"

    def scan(self) -> List[Finding]:
        """Run all dependency checks."""
        self._check_python_dependencies()
        self._check_node_dependencies()
        self._check_outdated_dependencies()
        self._check_license_risks()
        return self.findings

    def _check_python_dependencies(self):
        """Check Python dependencies for known vulnerabilities."""
        requirements_files = ["requirements.txt", "Pipfile", "pyproject.toml"]

        for req_file in requirements_files:
            path = self.project_root / req_file
            if not path.exists():
                continue

            content = self._read_file(path)
            if not content:
                continue

            # Parse requirements.txt format
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse package name and version with optional whitespace
                match = re.match(r"([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9a-zA-Z_.-]+)", line)
                if not match:
                    continue

                name, operator, version = match.groups()
                name_lower = name.lower()

                # Check against known vulnerabilities
                vulns = KNOWN_VULNERABILITIES.get("python", {}).get(name_lower, [])
                for vuln in vulns:
                    if self._version_matches(version, vuln["version"]):
                        self._add_finding(Finding(
                            category=self.category,
                            severity=vuln["severity"],
                            title=f"Vulnerable Dependency: {name} {version}",
                            description=f"The dependency '{name}' version {version} has a known vulnerability: {vuln['description']}",
                            evidence=f"{req_file}: {name}{operator}{version} | {vuln['cve']}: {vuln['description']}",
                            file_path=req_file,
                            confidence="high",
                            recommendation=f"Upgrade {name} to a version that fixes {vuln['cve']}. Run 'pip install --upgrade {name}' or update your requirements.txt.",
                            metadata={
                                "dependency": name,
                                "version": version,
                                "cve": vuln["cve"],
                                "ecosystem": "python",
                                "detection_source": "DEPENDENCY"
                            }
                        ))

    def _check_node_dependencies(self):
        """Check Node.js dependencies for known vulnerabilities."""
        package_json = self.project_root / "package.json"
        if not package_json.exists():
            return

        content = self._read_file(package_json)
        if not content:
            return

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

        for name, version in deps.items():
            name_lower = name.lower()
            vulns = KNOWN_VULNERABILITIES.get("node", {}).get(name_lower, [])

            for vuln in vulns:
                # Clean version string
                clean_version = version.lstrip("^~>=<")
                if self._version_matches(clean_version, vuln["version"]):
                    self._add_finding(Finding(
                        category=self.category,
                        severity=vuln["severity"],
                        title=f"Vulnerable Dependency: {name} {version}",
                        description=f"The dependency '{name}' version {version} has a known vulnerability: {vuln['description']}",
                        evidence=f"package.json: {name}@{version} | {vuln['cve']}: {vuln['description']}",
                        file_path="package.json",
                        confidence="high",
                        recommendation=f"Upgrade {name} to a version that fixes {vuln['cve']}. Run 'npm audit fix' or update package.json.",
                        metadata={
                            "dependency": name,
                            "version": version,
                            "cve": vuln["cve"],
                            "ecosystem": "node",
                            "detection_source": "DEPENDENCY"
                        }
                    ))

    def _check_outdated_dependencies(self):
        """Check for severely outdated dependencies."""
        requirements_files = ["requirements.txt", "package.json"]

        for req_file in requirements_files:
            path = self.project_root / req_file
            if not path.exists():
                continue

            content = self._read_file(path)
            if not content:
                continue

            # Check for very old versions (major version 0 or 1 for mature packages)
            old_version_pattern = r"([a-zA-Z0-9_-]+)([=<>!~]+)(0\.[0-9]+\.[0-9]+)"
            for match in re.finditer(old_version_pattern, content):
                name, operator, version = match.groups()
                self._add_finding(Finding(
                    category=self.category,
                    severity="low",
                    title=f"Pre-release Dependency Version: {name} {version}",
                    description=f"The dependency '{name}' is pinned to a pre-release version {version}. Pre-release versions may lack security patches.",
                    evidence=f"{req_file}: {name}{operator}{version}",
                    file_path=req_file,
                    confidence="medium",
                    recommendation=f"Consider upgrading {name} to a stable release version for better security support.",
                    metadata={
                        "dependency": name,
                        "version": version,
                        "detection_source": "DEPENDENCY"
                    }
                ))

    def _check_license_risks(self):
        """Check for potentially problematic licenses."""
        # This is a simplified check - real implementation would use license databases
        risky_packages = {
            "python": ["pycrypto"],  # Known abandoned package
            "node": ["event-stream", "flatmap-stream"],  # Known malicious packages
        }

        requirements_files = ["requirements.txt", "package.json"]
        for req_file in requirements_files:
            path = self.project_root / req_file
            if not path.exists():
                continue

            content = self._read_file(path)
            if not content:
                continue

            content_lower = content.lower()
            for pkg in risky_packages.get("python", []) + risky_packages.get("node", []):
                if pkg in content_lower:
                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Risky Dependency Detected: {pkg}",
                        description=f"The package '{pkg}' has known security issues or has been abandoned/malicious.",
                        evidence=f"{req_file} contains reference to '{pkg}'",
                        file_path=req_file,
                        confidence="high",
                        recommendation=f"Remove '{pkg}' from dependencies and use a maintained alternative.",
                        metadata={
                            "dependency": pkg,
                            "detection_source": "DEPENDENCY"
                        }
                    ))

    def _version_matches(self, installed: str, constraint: str) -> bool:
        """Check if installed version matches vulnerability constraint."""
        try:
            # Parse constraint like "<2.2.28"
            match = re.match(r"([<>=!~]+)([0-9.]+)", constraint)
            if not match:
                return False

            operator, target = match.groups()

            def parse_ver(v_str: str) -> list[int]:
                parts = re.findall(r"\d+", v_str)
                return [int(p) for p in parts] if parts else [0]

            installed_parts = parse_ver(installed)
            target_parts = parse_ver(target)

            # Pad to same length
            max_len = max(len(installed_parts), len(target_parts))
            installed_parts += [0] * (max_len - len(installed_parts))
            target_parts += [0] * (max_len - len(target_parts))

            if operator == "<":
                return installed_parts < target_parts
            elif operator == "<=":
                return installed_parts <= target_parts
            elif operator == ">":
                return installed_parts > target_parts
            elif operator == ">=":
                return installed_parts >= target_parts
            elif operator in ("==", "="):
                return installed_parts == target_parts
        except Exception:
            return False
        return False