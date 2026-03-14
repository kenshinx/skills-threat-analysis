"""Download a skill archive from a URL and convert it to a SkillFile."""

from __future__ import annotations

import hashlib
import logging
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests

from scanner.loader import (
    SUPPORTED_EXTENSIONS,
    _collect_auxiliary_content,
    _collect_file_hashes,
    _find_entry_file,
    _hash_bytes,
    _normalize_zip_root,
    detect_source,
)
from scanner.models import SkillFile

logger = logging.getLogger(__name__)

_DOWNLOAD_TIMEOUT = 120  # seconds


def _filename_from_url(url: str) -> str:
    """Extract a clean filename from a URL, stripping query params."""
    path = urlparse(url).path.rstrip("/")
    name = path.rsplit("/", 1)[-1] if "/" in path else path
    return name or "unnamed"


def _generate_skill_id(name: str, url: str) -> str:
    """Build a skill ID from the filename + a short hash of the full URL."""
    stem = Path(name).stem if "." in name else name
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in stem).strip("-")
    if not safe:
        safe = "unnamed"
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:8]
    return f"{safe}-{url_hash}"


def download_and_load(url: str, *, timeout: int = _DOWNLOAD_TIMEOUT) -> SkillFile:
    """Download an archive from *url*, extract it, and return a SkillFile.

    Supports:
    - ZIP archives (detected by content or extension)
    - Single-file downloads (.md, .yaml, .yml, .txt, .json)
    """
    with tempfile.TemporaryDirectory() as tmp_root:
        tmp = Path(tmp_root)
        archive_path = tmp / "skill_archive"

        logger.info("Downloading skill from %s", url)
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()

        with open(archive_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        if zipfile.is_zipfile(archive_path):
            return _load_from_zip(archive_path, url)

        return _load_single_file(archive_path, url)


def _load_from_zip(archive_path: Path, url: str) -> SkillFile:
    """Extract a ZIP and build a SkillFile from its contents."""
    extract_dir = archive_path.parent / "extracted"
    extract_dir.mkdir()

    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(extract_dir)

    # Normalize: unwrap single top-level directory per spec §4.1
    skill_root = _normalize_zip_root(extract_dir)
    entry = _find_entry_file(skill_root)

    filename = _filename_from_url(url)
    if entry is None:
        all_files = _collect_all_text(extract_dir)
        if not all_files:
            raise ValueError(f"No readable skill content found in archive from {url}")
        content = all_files
        file_path = url
        entry_file = filename
    else:
        content = entry.read_text(encoding="utf-8", errors="replace")
        aux = _collect_auxiliary_content(skill_root, entry)
        if aux:
            content += aux
        file_path = entry.name
        entry_file = entry.relative_to(skill_root).as_posix()

    source = detect_source(Path(filename))
    skill_id = _generate_skill_id(filename, url)

    file_md5s, file_sha1s = _collect_file_hashes(skill_root)
    pkg_md5, pkg_sha1 = _hash_bytes(archive_path.read_bytes())

    return SkillFile(
        id=skill_id,
        source=source,
        file_path=file_path,
        content=content,
        size_bytes=len(content.encode("utf-8")),
        name=Path(filename).stem,
        entry_file=entry_file,
        skill_dir=str(skill_root),
        file_md5s=file_md5s,
        file_sha1s=file_sha1s,
        package_md5=pkg_md5,
        package_sha1=pkg_sha1,
    )


def _load_single_file(file_path: Path, url: str) -> SkillFile:
    """Load a non-archive download as a single SkillFile."""
    raw = file_path.read_bytes()
    content = raw.decode("utf-8", errors="replace")
    filename = _filename_from_url(url)
    source = detect_source(Path(filename))
    skill_id = _generate_skill_id(filename, url)

    m, s = _hash_bytes(raw)
    rel = filename

    return SkillFile(
        id=skill_id,
        source=source,
        file_path=url,
        content=content,
        size_bytes=len(raw),
        name=Path(filename).stem,
        entry_file=filename,
        skill_dir="",
        file_md5s={rel: m},
        file_sha1s={rel: s},
    )


def _collect_all_text(directory: Path) -> str:
    """Fallback: concatenate all supported text files in a directory."""
    parts: list[str] = []
    for p in sorted(directory.rglob("*")):
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
            try:
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(parts)
