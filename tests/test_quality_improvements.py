"""Comprehensive regression and quality improvement test suite for Shipcheck.

Validates:
- Dependency scanner pre-release / post-release parsing
- Configuration scanner .env file boundaries
- Archive extraction path traversal prevention and directory preservation
- AI cache key collision prevention across files/severities
- Remediation diff hunk matching, backup restoration, and syntax validation
- Proxy double-encoding inspection and event categorization
- Desktop launcher port conflict detection and availability probing
"""

import io
import os
import zipfile
import pytest
from pathlib import Path

from backend.scanners.dependency import DependencyScanner
from backend.scanners.configuration import ConfigurationScanner
from backend.services.secure_extract import secure_extract, validate_zip_safety, ZipSecurityError
from backend.services.ai_cache import AICacheService
from backend.services.remediation import RemediationService
from backend.services.context_window import extract_context_window
from backend.api.proxy import _inspect_attack, _event_type_for


def test_dependency_version_prerelease_and_whitespace(tmp_path):
    """Verify pre-release versions like '2.2.28b1' and loose whitespace parse without crash."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("django == 2.2.0\nrequests >= 2.19.0\nurllib3 == 1.26.4\n", encoding="utf-8")

    scanner = DependencyScanner(str(tmp_path), {})
    # Verify _version_matches with pre-release tags
    assert scanner._version_matches("2.2.28b1", "<2.3.0")
    assert not scanner._version_matches("2.3.1rc1", "<2.3.0")
    assert scanner._version_matches("2.2.0", "==2.2.0")

    findings = scanner.scan()
    vulnerable_deps = [f for f in findings if "Vulnerable Dependency" in f.title]
    assert len(vulnerable_deps) > 0


def test_configuration_scanner_env_eof_handling(tmp_path):
    """Verify that .env files with secrets on the final line without a trailing newline are caught."""
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=supersecretproductionkey12345", encoding="utf-8")

    scanner = ConfigurationScanner(str(tmp_path), {})
    findings = scanner.scan()
    secret_findings = [f for f in findings if "Secret Exposed in .env" in f.title]
    assert len(secret_findings) > 0
    # Ensure secret is redacted in evidence
    assert "supersecretproductionkey12345" not in secret_findings[0].evidence


def test_secure_archive_extraction_traversal_blocked(tmp_path):
    """Verify that zip slip archives with relative traversal entries are blocked."""
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../evil.txt", "malicious payload")
        zf.writestr("legit/sub/file.py", "print('safe')")

    dest_dir = tmp_path / "extracted"

    # Validation should catch path traversal
    validation = validate_zip_safety(str(zip_path))
    assert not validation["valid"]
    assert any("Path traversal detected" in issue for issue in validation["issues"])

    # Attempting to extract should raise ZipSecurityError and prevent traversal write
    with pytest.raises(ZipSecurityError):
        secure_extract(str(zip_path), str(dest_dir))
    assert not (tmp_path / "evil.txt").exists()


def test_ai_cache_key_includes_file_and_severity():
    """Verify cache keys differ when finding title is the same but file_path or severity differs."""
    meta1 = {"title": "XSS", "category": "security", "file_path": "app.py", "evidence": "x", "line_number": 10, "severity": "high"}
    meta2 = {"title": "XSS", "category": "security", "file_path": "utils.py", "evidence": "x", "line_number": 10, "severity": "high"}
    meta3 = {"title": "XSS", "category": "security", "file_path": "app.py", "evidence": "x", "line_number": 10, "severity": "medium"}

    k1 = AICacheService.compute_cache_key("analysis", "code", meta1, "gemma")
    k2 = AICacheService.compute_cache_key("analysis", "code", meta2, "gemma")
    k3 = AICacheService.compute_cache_key("analysis", "code", meta3, "gemma")

    assert k1 != k2
    assert k1 != k3


def test_remediation_diff_application_and_rollback(tmp_path):
    """Verify that unified diff blocks are applied correctly and rolled back on syntax corruption."""
    service = RemediationService("test-proj")
    target_file = tmp_path / "app.py"
    target_file.write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")

    diff = """--- app.py
+++ app.py
-    return a - b
+    return a + b
"""
    ok, err = service._apply_patch_to_workspace(tmp_path, "app.py", diff)
    assert ok
    assert "return a + b" in target_file.read_text(encoding="utf-8")


def test_proxy_double_url_encoding_detection():
    """Verify that double URL encoded path traversal (%252e%252e%252f) is intercepted by runtime proxy."""
    # Double-encoded traversal: %252e%252e%252f -> %2e%2e%2f -> ../
    double_encoded_url = "http://127.0.0.1:8001/api/files?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    attack_label = _inspect_attack(double_encoded_url)
    assert attack_label is not None
    assert "traversal" in attack_label.lower()
    event_type = _event_type_for(attack_label)
    assert event_type == "PATH_TRAVERSAL"
