"""Secure ZIP extraction service with defense-in-depth protections."""

import os
import zipfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
import re

MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500MB total extracted
MAX_FILES = 10000
MAX_COMPRESSION_RATIO = 50  # Detect zip bombs
MAX_EXTRACT_DEPTH = 10

# Dangerous path patterns
PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\)")
ABSOLUTE_PATH_RE = re.compile(r"^(/|[A-Za-z]:\\\\|[A-Za-z]:/)")  # Unix /... or Windows C:\ or C:/
SYMLINK_RE = re.compile(r"symlink", re.IGNORECASE)
DEV_RE = re.compile(r"/dev/|/proc/|/sys/")


class ZipSecurityError(Exception):
    """Raised when ZIP security checks fail."""
    pass


def validate_zip_safety(zip_path: str) -> Dict[str, Any]:
    """Validate a ZIP file for security risks before extraction."""
    path = Path(zip_path)
    if not path.exists():
        raise ZipSecurityError("File not found")

    size = path.stat().st_size
    if size > MAX_ZIP_SIZE:
        raise ZipSecurityError(f"ZIP file too large: {size} bytes (max {MAX_ZIP_SIZE})")

    issues = []
    total_uncompressed = 0
    file_count = 0
    max_depth = 0

    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                file_count += 1
                if file_count > MAX_FILES:
                    issues.append(f"Too many files: {file_count} (max {MAX_FILES})")
                    break

                # Check path traversal
                name = info.filename
                if PATH_TRAVERSAL_RE.search(name):
                    issues.append(f"Path traversal detected: {name}")
                    continue

                # Check absolute paths
                if ABSOLUTE_PATH_RE.search(name):
                    issues.append(f"Absolute path detected: {name}")
                    continue

                # Check for symlinks
                if info.create_system == 3 and info.external_attr >> 16 & 0o170000 == 0o120000:
                    issues.append(f"Symlink detected: {name}")
                    continue

                # Check for device/proc/sys paths
                if DEV_RE.search(name):
                    issues.append(f"System path detected: {name}")
                    continue

                # Check compression ratio (zip bomb detection)
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO:
                        issues.append(f"Possible zip bomb: {name} (ratio {ratio:.1f})")

                total_uncompressed += info.file_size
                max_depth = max(max_depth, len(Path(name).parts))

            if total_uncompressed > MAX_EXTRACTED_SIZE:
                issues.append(f"Total uncompressed size too large: {total_uncompressed} (max {MAX_EXTRACTED_SIZE})")

            if max_depth > MAX_EXTRACT_DEPTH:
                issues.append(f"Directory depth too deep: {max_depth} (max {MAX_EXTRACT_DEPTH})")

    except zipfile.BadZipFile as e:
        raise ZipSecurityError(f"Invalid ZIP file: {e}")
    except Exception as e:
        raise ZipSecurityError(f"ZIP validation error: {e}")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "file_count": file_count,
        "total_size": size,
        "total_uncompressed": total_uncompressed,
        "max_depth": max_depth,
    }


def secure_extract(zip_path: str, dest_dir: str) -> Dict[str, Any]:
    """Securely extract a validated ZIP file."""
    validation = validate_zip_safety(zip_path)
    if not validation["valid"]:
        raise ZipSecurityError(f"ZIP failed security checks: {validation['issues']}")

    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    extracted_files = []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                name = info.filename

                # Skip directories
                if name.endswith("/") or name.endswith("\\") or info.is_dir():
                    continue

                # Re-validate each entry for traversal or absolute root
                if PATH_TRAVERSAL_RE.search(name) or ABSOLUTE_PATH_RE.search(name):
                    raise ZipSecurityError(f"Path traversal blocked: {name}")

                # Build target path
                target_path = (dest / name).resolve()
                if not target_path.is_relative_to(dest):
                    raise ZipSecurityError(f"Path traversal blocked: {name}")

                # Create parent directories safely
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract content directly to validated destination
                with zf.open(info) as src, open(target_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                extracted_files.append(str(target_path.relative_to(dest)))

        return {
            "success": True,
            "extracted_count": len(extracted_files),
            "files": extracted_files[:100],  # Limit returned list
            "total_size": validation["total_size"],
        }

    except Exception as e:
        # Cleanup on failure
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        raise ZipSecurityError(f"Extraction failed: {e}")


def get_zip_info(zip_path: str) -> Dict[str, Any]:
    """Get basic information about a ZIP file."""
    path = Path(zip_path)
    if not path.exists():
        raise ZipSecurityError("File not found")

    try:
        with zipfile.ZipFile(path, "r") as zf:
            files = []
            for info in zf.infolist():
                files.append({
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                    "is_dir": info.filename.endswith("/"),
                })

            return {
                "file_count": len(files),
                "total_size": path.stat().st_size,
                "files": files[:200],
            }
    except zipfile.BadZipFile as e:
        raise ZipSecurityError(f"Invalid ZIP: {e}")