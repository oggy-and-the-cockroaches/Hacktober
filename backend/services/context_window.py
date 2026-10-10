"""Source code context extraction and windowing utilities."""

import ast
from typing import Optional


def extract_context_window(
    file_content: str,
    target_line: Optional[int] = None,
    window_radius: int = 25,
    include_line_numbers: bool = True
) -> str:
    """Extract a windowed context around target_line with relevant imports and scope."""
    if not file_content:
        return ""

    lines = file_content.splitlines()
    total_lines = len(lines)

    if total_lines <= 50 or not target_line:
        if include_line_numbers:
            return "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines))
        return file_content

    # Normalize target_line (1-indexed)
    line_idx = max(1, min(target_line, total_lines)) - 1

    # Extract imports from the top of the file
    imports = []
    for i, line in enumerate(lines[:30]):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            imports.append(f"{i + 1}: {line}" if include_line_numbers else line)

    start_idx = max(0, line_idx - window_radius)
    end_idx = min(total_lines, line_idx + window_radius + 1)

    windowed_lines = []
    if imports and start_idx > 30:
        windowed_lines.append("# --- Relevant Imports ---")
        windowed_lines.extend(imports)
        windowed_lines.append(f"# --- Context Window around line {target_line} ---")

    for idx in range(start_idx, end_idx):
        windowed_lines.append(f"{idx + 1}: {lines[idx]}" if include_line_numbers else lines[idx])

    return "\n".join(windowed_lines)
