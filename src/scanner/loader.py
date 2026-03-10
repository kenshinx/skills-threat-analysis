"""File loader: traverse directories and read skill content."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Generator

from scanner.models import SkillFile

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".md", ".yaml", ".yml", ".txt", ".json"}

# Source detection by directory name
_SOURCE_KEYWORDS = {
    "clawhub": "clawhub",
    "smithery": "smithery",
    "skills_sh": "skills_sh",
    "skills.sh": "skills_sh",
}


def detect_source(file_path: Path) -> str:
    parts = [p.lower() for p in file_path.parts]
    for keyword, source in _SOURCE_KEYWORDS.items():
        if keyword in parts:
            return source
    return "unknown"


def generate_id(source: str, file_path: Path) -> str:
    path_hash = hashlib.sha256(str(file_path).encode()).hexdigest()[:12]
    return f"{source}-{path_hash}"


def load_skills(
    root_dir: str | Path,
    extensions: set[str] | None = None,
) -> Generator[SkillFile, None, None]:
    """Yield SkillFile objects from the given directory tree.

    Streams files one at a time to keep memory usage low.
    """
    root = Path(root_dir)
    exts = extensions or SUPPORTED_EXTENSIONS

    if not root.exists():
        logger.error("Directory does not exist: %s", root)
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            source = detect_source(path)
            yield SkillFile(
                id=generate_id(source, path),
                source=source,
                file_path=str(path),
                content=content,
                size_bytes=path.stat().st_size,
            )
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
