"""File loader: traverse directories and read skill content."""

from __future__ import annotations

import hashlib
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Generator

from scanner.models import SkillFile

logger = logging.getLogger(__name__)

# Known skill entry file names (case-insensitive matching)
SKILL_ENTRY_NAMES = {"skill.md", "skill.yaml", "skill.yml"}

SUPPORTED_EXTENSIONS = {".md", ".yaml", ".yml", ".txt", ".json"}

# Files to ignore when scanning directories
IGNORED_FILES = {"detail.json"}

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


def _find_entry_file(skill_dir: Path) -> Path | None:
    """Find the skill entry file (SKILL.md etc.) in a directory."""
    for child in skill_dir.iterdir():
        if child.is_file() and child.name.lower() in SKILL_ENTRY_NAMES:
            return child
    return None


def _collect_auxiliary_content(skill_dir: Path, entry_file: Path) -> str:
    """Read all auxiliary files (references, examples, etc.) and concatenate."""
    parts = []
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or path == entry_file:
            continue
        if path.name.lower() in IGNORED_FILES:
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            rel = path.relative_to(skill_dir)
            parts.append(f"\n--- [{rel}] ---\n{text}")
        except OSError:
            continue
    return "\n".join(parts)


def _find_zip_files(directory: Path) -> list[Path]:
    """Find all .zip files in a directory, ignoring non-skill files."""
    return [
        f for f in sorted(directory.iterdir())
        if f.is_file() and f.suffix.lower() == ".zip"
    ]


def _load_skill_from_zip(
    zip_path: Path,
    original_dir: Path,
) -> Generator[SkillFile, None, None]:
    """Extract a zip file to a temp directory and load the skill from it."""
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)

            # Look for entry file in extracted contents
            entry = _find_entry_file(tmp)
            if entry is None:
                # Check one level deeper (zip may have a wrapper dir)
                for sub in sorted(tmp.iterdir()):
                    if sub.is_dir():
                        entry = _find_entry_file(sub)
                        if entry:
                            tmp = sub
                            break

            if entry is None:
                logger.debug("No skill entry file in zip: %s", zip_path)
                return

            # Build SkillFile but use original_dir for source/id/path
            entry_content = entry.read_text(encoding="utf-8", errors="replace")
            aux_content = _collect_auxiliary_content(tmp, entry)
            full_content = entry_content + aux_content
            source = detect_source(original_dir)

            yield SkillFile(
                id=generate_id(source, original_dir),
                source=source,
                file_path=str(original_dir / zip_path.name),
                content=full_content,
                size_bytes=len(full_content.encode("utf-8")),
            )
    except (zipfile.BadZipFile, OSError) as e:
        logger.warning("Failed to process zip %s: %s", zip_path, e)


def load_skills(
    root_dir: str | Path,
    extensions: set[str] | None = None,
) -> Generator[SkillFile, None, None]:
    """Yield SkillFile objects from the given directory tree.

    Supports three layouts:
    1. Zip-based: <root>/<author>/<skill>/*.zip (clawhub_data style)
    2. Directory-based: directories containing SKILL.md
    3. Flat files: individual text files as fallback
    """
    root = Path(root_dir)

    if not root.exists():
        logger.error("Directory does not exist: %s", root)
        return

    visited_dirs: set[Path] = set()

    for skill_dir in sorted(root.iterdir()):
        if not skill_dir.is_dir():
            continue

        # Check if this directory directly contains zip files (flat zip layout)
        zips = _find_zip_files(skill_dir)
        if zips:
            for zp in zips:
                yield from _load_skill_from_zip(zp, skill_dir)
            visited_dirs.add(skill_dir)
            continue

        # Check if this is a skill directory with an entry file
        entry = _find_entry_file(skill_dir)
        if entry is not None:
            yield from _load_one_skill(skill_dir, entry)
            visited_dirs.add(skill_dir)
            continue

        # Not a direct skill dir — scan subdirectories (author/<skill>/ layout)
        for sub in sorted(skill_dir.rglob("*")):
            if not sub.is_dir():
                continue

            # Check for zips in subdirectory
            sub_zips = _find_zip_files(sub)
            if sub_zips:
                for zp in sub_zips:
                    yield from _load_skill_from_zip(zp, sub)
                visited_dirs.add(sub)
                continue

            # Check for entry file in subdirectory
            sub_entry = _find_entry_file(sub)
            if sub_entry:
                yield from _load_one_skill(sub, sub_entry)
                visited_dirs.add(sub)

    # If root itself has an entry file (flat structure)
    root_entry = _find_entry_file(root)
    if root_entry:
        yield from _load_one_skill(root, root_entry)

    # Fallback: if root has no subdirectories with SKILL.md, treat individual
    # files as skills (backward compatibility for flat file collections)
    if not visited_dirs and not root_entry:
        exts = extensions or SUPPORTED_EXTENSIONS
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


def _load_one_skill(skill_dir: Path, entry: Path) -> Generator[SkillFile, None, None]:
    """Load a single skill directory as one SkillFile."""
    try:
        entry_content = entry.read_text(encoding="utf-8", errors="replace")
        aux_content = _collect_auxiliary_content(skill_dir, entry)
        full_content = entry_content + aux_content
        source = detect_source(skill_dir)

        yield SkillFile(
            id=generate_id(source, skill_dir),
            source=source,
            file_path=str(entry),
            content=full_content,
            size_bytes=len(full_content.encode("utf-8")),
        )
    except OSError as e:
        logger.warning("Failed to read skill at %s: %s", skill_dir, e)
