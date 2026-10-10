"""Secure project workspace manager."""

import json
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List

from backend.database.schema import get_project_dir


class WorkspaceManager:
    """Manage isolated project workspaces with secure file operations."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.project_dir = get_project_dir(project_id)
        self._ensure_structure()

    def _ensure_structure(self):
        for subdir in ("source", "metadata", "temporary", "reports"):
            (self.project_dir / subdir).mkdir(parents=True, exist_ok=True)

    def get_workspace_path(self, *parts: str) -> Path:
        return self.resolve_safe_path("/".join(parts))

    def resolve_safe_path(self, relative_path: str) -> Path:
        candidate = Path(relative_path)

        if candidate.is_absolute():
            raise ValueError("Absolute path not allowed: " + relative_path)

        full_path = (self.project_dir / candidate).resolve()
        workspace_root = self.project_dir.resolve()

        try:
            full_path.relative_to(workspace_root)
        except ValueError:
            raise ValueError("Path traversal detected: " + relative_path)

        return full_path

    def create_temp_file(self, prefix: str = "tmp", suffix: str = "") -> Path:
        temp_dir = self.project_dir / "temporary"
        temp_dir.mkdir(parents=True, exist_ok=True)

        name = prefix + "_" + uuid.uuid4().hex[:8] + suffix
        return temp_dir / name

    def cleanup_temporary(self):
        temp_dir = self.project_dir / "temporary"

        if temp_dir.exists():
            shutil.rmtree(temp_dir)

        temp_dir.mkdir(parents=True, exist_ok=True)

    def save_metadata(self, metadata: Dict[str, Any]):
        meta_path = self.project_dir / "metadata" / "project.json"
        meta_path.parent.mkdir(parents=True, exist_ok=True)

        meta_path.write_text(
            json.dumps(metadata, indent=2, default=str),
            encoding="utf-8",
        )

    def load_metadata(self) -> Optional[Dict[str, Any]]:
        meta_path = self.project_dir / "metadata" / "project.json"

        if not meta_path.exists():
            return None

        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def list_files(self, subdirectory: str = "source") -> List[str]:
        target_dir = self.resolve_safe_path(subdirectory)

        if not target_dir.exists():
            return []

        return [
            str(item.relative_to(self.project_dir))
            for item in target_dir.rglob("*")
            if item.is_file()
        ]

    def delete_workspace(self):
        if self.project_dir.exists():
            shutil.rmtree(self.project_dir)

    def get_disk_usage(self) -> Dict[str, Any]:
        total_size = 0
        file_count = 0

        if self.project_dir.exists():
            for item in self.project_dir.rglob("*"):
                if item.is_file():
                    total_size += item.stat().st_size
                    file_count += 1

        return {
            "total_size_bytes": total_size,
            "file_count": file_count,
            "workspace_path": str(self.project_dir),
        }


def get_workspace(project_id: str) -> WorkspaceManager:
    return WorkspaceManager(project_id)