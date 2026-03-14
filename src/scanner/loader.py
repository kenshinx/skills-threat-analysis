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

SUPPORTED_EXTENSIONS = {".md", ".yaml", ".yml", ".txt", ".json", ".svg", ".html", ".htm", ".xml",
                        ".py", ".js", ".ts", ".sh", ".bash"}

# Maximum bytes per auxiliary file; files larger than this are skipped.
_MAX_AUX_FILE_BYTES = 200 * 1024  # 200 KB
# Maximum total content bytes per skill (entry + all aux files combined).
_MAX_TOTAL_CONTENT_BYTES = 1 * 1024 * 1024  # 1 MB

# Files to ignore when scanning directories
IGNORED_FILES = {"detail.json"}

# Source detection by directory name
_SOURCE_KEYWORDS = {
    "clawhub": "clawhub",
    "smithery": "smithery",
    "skills_sh": "skills_sh",
    "skills.sh": "skills_sh",
}


def _hash_bytes(data: bytes) -> tuple[str, str]:
    """Return (md5_hex, sha1_hex) for the given bytes."""
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()


def _collect_file_hashes(root_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Walk *all* files under *root_dir* and return (file_md5s, file_sha1s).

    Keys are POSIX-style relative paths (e.g. ``bin/run.js``).
    """
    md5s: dict[str, str] = {}
    sha1s: dict[str, str] = {}
    for p in sorted(root_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
            rel = p.relative_to(root_dir).as_posix()
            m, s = _hash_bytes(data)
            md5s[rel] = m
            sha1s[rel] = s
        except OSError:
            continue
    return md5s, sha1s


def detect_source(file_path: Path) -> str:
    """Detect source platform from path using substring matching.

    Matches keywords against individual path components using substring check,
    so 'clawhub_data' matches keyword 'clawhub'.
    """
    parts = [p.lower() for p in file_path.parts]
    for keyword, source in _SOURCE_KEYWORDS.items():
        for part in parts:
            if keyword in part:
                return source
    return "unknown"


def generate_id(file_path: Path) -> str:
    """Generate skill ID using directory name as prefix + short hash for uniqueness."""
    dir_name = file_path.name if file_path.is_dir() else file_path.stem
    # Sanitize: keep only alphanumeric, hyphen, underscore
    safe_name = "".join(
        c if c.isalnum() or c in "-_" else "-" for c in dir_name).strip("-")
    if not safe_name:
        safe_name = "unnamed"
    path_hash = hashlib.sha256(str(file_path).encode()).hexdigest()[:8]
    return f"{safe_name}-{path_hash}"


def _find_entry_file(skill_dir: Path) -> Path | None:
    """Find the skill entry file (SKILL.md etc.) in a directory."""
    for child in skill_dir.iterdir():
        if child.is_file() and child.name.lower() in SKILL_ENTRY_NAMES:
            return child
    return None


def _collect_auxiliary_content(skill_dir: Path, entry_file: Path) -> str:
    """Read all auxiliary files (references, examples, etc.) and concatenate."""
    parts = []
    total_bytes = 0
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or path == entry_file:
            continue
        if path.name.lower() in IGNORED_FILES:
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            file_size = path.stat().st_size
            if total_bytes >= _MAX_TOTAL_CONTENT_BYTES:
                logger.debug(
                    "Total content limit reached (%d KB), skipping remaining aux files",
                    _MAX_TOTAL_CONTENT_BYTES // 1024,
                )
                break
            rel = path.relative_to(skill_dir)
            if file_size > _MAX_AUX_FILE_BYTES:
                # Read only the head of oversized files — malicious payloads
                # are typically embedded at the start; the rest may be padding.
                with path.open("rb") as fh:
                    raw = fh.read(_MAX_AUX_FILE_BYTES)
                text = raw.decode("utf-8", errors="replace")
                parts.append(
                    f"\n--- [{rel}] (truncated {file_size // 1024} KB → {_MAX_AUX_FILE_BYTES // 1024} KB) ---\n{text}"
                )
                total_bytes += _MAX_AUX_FILE_BYTES
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
                parts.append(f"\n--- [{rel}] ---\n{text}")
                total_bytes += file_size
        except OSError:
            continue
    return "\n".join(parts)


SKILL_ARCHIVE_EXTENSIONS = {".zip", ".skill"}


def _find_zip_files(directory: Path) -> list[Path]:
    """Find all .zip / .skill archive files in a directory."""
    return [
        f for f in sorted(directory.iterdir())
        if f.is_file() and f.suffix.lower() in SKILL_ARCHIVE_EXTENSIONS
    ]


def _normalize_zip_root(tmp: Path) -> Path:
    """Implement spec §4.1: unwrap single top-level directory if no top-level files exist."""
    children = list(tmp.iterdir())
    top_dirs = [c for c in children if c.is_dir()]
    top_files = [c for c in children if c.is_file()]
    if len(top_dirs) == 1 and len(top_files) == 0:
        return top_dirs[0]
    return tmp


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

            # Normalize: unwrap single top-level directory per spec §4.1
            root = _normalize_zip_root(tmp)

            entry = _find_entry_file(root)
            if entry is None:
                logger.debug("No skill entry file in zip: %s", zip_path)
                return

            # Build SkillFile but use original_dir for source/id/path
            entry_content = entry.read_text(encoding="utf-8", errors="replace")
            aux_content = _collect_auxiliary_content(root, entry)
            full_content = entry_content + aux_content
            source = detect_source(original_dir)

            file_md5s, file_sha1s = _collect_file_hashes(root)
            pkg_md5, pkg_sha1 = _hash_bytes(zip_path.read_bytes())

            yield SkillFile(
                id=generate_id(original_dir),
                source=source,
                file_path=str(original_dir / zip_path.name),
                content=full_content,
                size_bytes=len(full_content.encode("utf-8")),
                name=original_dir.name,
                entry_file=entry.relative_to(root).as_posix(),
                skill_dir=str(original_dir),
                file_md5s=file_md5s,
                file_sha1s=file_sha1s,
                package_md5=pkg_md5,
                package_sha1=pkg_sha1,
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
                raw = path.read_bytes()
                content = raw.decode("utf-8", errors="replace")
                source = detect_source(path)
                m, s = _hash_bytes(raw)
                rel = path.name
                yield SkillFile(
                    id=generate_id(path),
                    source=source,
                    file_path=str(path),
                    content=content,
                    size_bytes=len(raw),
                    name=path.stem,
                    entry_file=path.name,
                    skill_dir=str(path.parent),
                    file_md5s={rel: m},
                    file_sha1s={rel: s},
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
        file_md5s, file_sha1s = _collect_file_hashes(skill_dir)

        yield SkillFile(
            id=generate_id(skill_dir),
            source=source,
            file_path=str(entry),
            content=full_content,
            size_bytes=len(full_content.encode("utf-8")),
            name=skill_dir.name,
            entry_file=entry.relative_to(skill_dir).as_posix(),
            skill_dir=str(skill_dir),
            file_md5s=file_md5s,
            file_sha1s=file_sha1s,
        )
    except OSError as e:
        logger.warning("Failed to read skill at %s: %s", skill_dir, e)
