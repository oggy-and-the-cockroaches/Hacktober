import json
import pytest

from backend.services.workspace import WorkspaceManager


def test_workspace_creation(tmp_path, monkeypatch):
    project_id = "test-project"
    workspace = WorkspaceManager(project_id)

    assert workspace.project_dir.exists()
    assert (workspace.project_dir / "source").exists()
    assert (workspace.project_dir / "metadata").exists()
    assert (workspace.project_dir / "temporary").exists()
    assert (workspace.project_dir / "reports").exists()


def test_safe_path_resolution():
    workspace = WorkspaceManager("test-safe-path")

    path = workspace.resolve_safe_path("source/app.py")

    assert path.is_absolute()
    assert "source" in path.parts
    assert path.name == "app.py"


def test_relative_path_traversal_rejected():
    workspace = WorkspaceManager("test-traversal")

    with pytest.raises(ValueError):
        workspace.resolve_safe_path("../../etc/passwd")


def test_absolute_path_rejected():
    workspace = WorkspaceManager("test-absolute")

    with pytest.raises(ValueError):
        workspace.resolve_safe_path("/etc/passwd")


def test_temporary_file():
    workspace = WorkspaceManager("test-temp")

    path = workspace.create_temp_file("scan", ".json")

    assert path.parent.name == "temporary"
    assert path.name.startswith("scan_")
    assert path.suffix == ".json"


def test_metadata_save_and_load():
    workspace = WorkspaceManager("test-metadata")

    metadata = {
        "name": "Test Project",
        "language": "Python",
        "version": 1,
    }

    workspace.save_metadata(metadata)

    loaded = workspace.load_metadata()

    assert loaded == metadata


def test_missing_metadata_returns_none():
    workspace = WorkspaceManager("test-missing-metadata")

    assert workspace.load_metadata() is None


def test_disk_usage():
    workspace = WorkspaceManager("test-disk-usage")

    source_file = workspace.project_dir / "source" / "example.txt"
    source_file.write_text("hello world", encoding="utf-8")

    usage = workspace.get_disk_usage()

    assert usage["file_count"] >= 1
    assert usage["total_size_bytes"] >= len("hello world")
    assert usage["workspace_path"] == str(workspace.project_dir)


def test_workspace_factory():
    from backend.services.workspace import get_workspace

    workspace = get_workspace("factory-test")

    assert isinstance(workspace, WorkspaceManager)
    assert workspace.project_id == "factory-test"
