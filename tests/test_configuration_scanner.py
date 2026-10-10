"""Tests for ConfigurationScanner."""

import tempfile
import os
from pathlib import Path
import pytest

from backend.scanners.configuration import ConfigurationScanner


class TestConfigurationScanner:
    """Test cases for ConfigurationScanner."""

    def setup_method(self):
        """Create a temporary project directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_root = Path(self.temp_dir)
        self.scanner = ConfigurationScanner(str(self.project_root), {})

    def teardown_method(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def write_file(self, filename: str, content: str):
        """Helper to write a file in the temp project."""
        (self.project_root / filename).write_text(content)

    def test_debug_mode_detection(self):
        """Test detection of debug mode in config files."""
        self.write_file("config.json", '{"debug": true, "port": 8000}')
        self.write_file("settings.py", 'DEBUG = True')
        self.write_file(".env", 'NODE_ENV=development')

        findings = self.scanner.scan()

        debug_findings = [f for f in findings if "Debug" in f.title]
        assert len(debug_findings) >= 2

        # Check evidence includes line numbers
        for f in debug_findings:
            assert f.line_number is not None
            assert f.detection_source == "CONFIGURATION"

    def test_unsafe_cors_detection(self):
        """Test detection of wildcard CORS."""
        self.write_file("config.yaml", 'cors:\n  allow_origins: "*"')
        self.write_file("app.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])')

        findings = self.scanner.scan()

        cors_findings = [f for f in findings if "CORS" in f.title or "cors" in f.title.lower()]
        assert len(cors_findings) >= 1
        assert cors_findings[0].severity == "medium"

    def test_ssl_verification_disabled(self):
        """Test detection of disabled SSL verification."""
        self.write_file("config.json", '{"ssl_verify": false}')
        self.write_file("settings.py", 'verify_ssl = False')

        findings = self.scanner.scan()

        ssl_findings = [f for f in findings if "SSL" in f.title or "ssl" in f.title.lower()]
        assert len(ssl_findings) >= 1
        assert ssl_findings[0].severity == "high"

    def test_secret_in_env_file_redacted(self):
        """Test secret detection in .env files with redaction."""
        self.write_file(".env", 'API_KEY=ab12cd34ef56gh78ij90kl12mn34op56qr78\nSECRET=mysecretpassword123')

        findings = self.scanner.scan()

        secret_findings = [f for f in findings if "Secret" in f.title or "secret" in f.title.lower()]
        assert len(secret_findings) >= 2

        # Check redaction in evidence
        for f in secret_findings:
            assert f.evidence is not None
            assert "*" in f.evidence or "[REDACTED]" in f.evidence
            assert "ab12cd34ef56gh78ij90kl12mn34op56qr78" not in f.evidence

    def test_secret_placeholder_not_flagged(self):
        """Test that placeholder secrets are not flagged."""
        self.write_file(".env", 'API_KEY=your_api_key_here\nSECRET=changeme\nPASSWORD=placeholder')

        findings = self.scanner.scan()

        secret_findings = [f for f in findings if "Secret" in f.title and "API Key" in f.title]
        # Should not flag placeholders
        assert len(secret_findings) == 0

    def test_docker_root_user_detection(self):
        """Test detection of root user in Dockerfile."""
        self.write_file("Dockerfile", 'FROM python:3.11\nCOPY . .\nCMD ["python", "app.py"]')

        findings = self.scanner.scan()

        docker_findings = [f for f in findings if "Docker" in f.title and "Root" in f.title]
        assert len(docker_findings) == 1
        # Severity can be low (for known non-root base images) or medium
        assert docker_findings[0].severity in ("low", "medium")

    def test_docker_latest_tag_detection(self):
        """Test detection of latest tag in Dockerfile."""
        self.write_file("Dockerfile", 'FROM python:latest\nCOPY . .')

        findings = self.scanner.scan()

        docker_findings = [f for f in findings if "latest" in f.title.lower()]
        assert len(docker_findings) == 1
        assert docker_findings[0].severity == "low"

    def test_docker_secret_copy_detection(self):
        """Test detection of secret files copied in Dockerfile."""
        self.write_file("Dockerfile", 'FROM python:3.11\nCOPY .env .\nCOPY id_rsa .')

        findings = self.scanner.scan()

        docker_findings = [f for f in findings if "Secret" in f.title and "Docker" in f.title]
        assert len(docker_findings) >= 1
        assert docker_findings[0].severity == "critical"

    def test_gitignore_missing(self):
        """Test detection of missing .gitignore."""
        # Don't create .gitignore
        findings = self.scanner.scan()

        gitignore_findings = [f for f in findings if "gitignore" in f.title.lower()]
        assert len(gitignore_findings) == 1
        assert gitignore_findings[0].severity == "medium"

    def test_gitignore_missing_entries(self):
        """Test detection of missing entries in .gitignore."""
        self.write_file(".gitignore", "__pycache__\n*.pyc")

        findings = self.scanner.scan()

        gitignore_findings = [f for f in findings if "gitignore" in f.title.lower() and "Missing" in f.title]
        assert len(gitignore_findings) == 1
        assert ".env" in gitignore_findings[0].evidence
        assert "node_modules" in gitignore_findings[0].evidence

    def test_hardcoded_secret_in_config(self):
        """Test detection of hardcoded secrets in config files."""
        self.write_file("config.json", '{"password": "supersecretpassword123", "api_key": "ab12cd34ef56gh78ij90kl12mn34op56"}')

        findings = self.scanner.scan()

        secret_findings = [f for f in findings if "Hardcoded" in f.title]
        assert len(secret_findings) >= 2

    def test_security_headers_missing(self):
        """Test detection of missing security headers."""
        self.write_file("middleware.py", 'def middleware():\n    pass\n    # No security headers here')

        findings = self.scanner.scan()

        header_findings = [f for f in findings if "Security Headers" in f.title]
        assert len(header_findings) >= 1

    def test_extended_fields_populated(self):
        """Test that all extended Finding fields are populated."""
        self.write_file("config.json", '{"debug": true}')

        findings = self.scanner.scan()

        debug_finding = next((f for f in findings if "Debug" in f.title), None)
        assert debug_finding is not None
        assert debug_finding.suggested_fix is not None
        assert debug_finding.existing_solution is not None
        assert debug_finding.project_specific_solution is not None
        assert debug_finding.detection_source == "CONFIGURATION"

    def test_safe_config_no_false_positive(self):
        """Test that safe configuration produces no findings."""
        self.write_file("config.json", '{"debug": false, "port": 8000, "ssl_verify": true}')
        self.write_file(".env", 'API_KEY=your_key_here\nDEBUG=false')

        findings = self.scanner.scan()

        # Should only have gitignore missing (since we didn't create one)
        # and maybe some info findings
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        assert len(critical_high) == 0

    def test_malformed_config_handling(self):
        """Test handling of malformed configuration files."""
        self.write_file("config.json", '{ invalid json }')
        self.write_file("config.yaml", 'invalid: yaml: content: [')

        findings = self.scanner.scan()

        # Should not crash
        assert isinstance(findings, list)

    def test_aws_keys_detection(self):
        """Test detection of AWS keys in .env files."""
        self.write_file(".env", 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

        findings = self.scanner.scan()

        aws_findings = [f for f in findings if "AWS" in f.title]
        assert len(aws_findings) == 2

    def test_debug_config_variants(self):
        """Test detection of various debug configuration patterns."""
        self.write_file("config.py", 'DEBUG = True')
        self.write_file("config.yaml", 'debug: true')
        self.write_file("config.json", '"debug": true')
        self.write_file(".env", 'NODE_ENV=development\nAPP_ENV=dev')

        findings = self.scanner.scan()

        debug_findings = [f for f in findings if "Debug" in f.title]
        # Should detect all variants
        assert len(debug_findings) >= 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])