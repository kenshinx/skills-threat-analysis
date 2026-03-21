"""Utility for loading and applying excluded-directory patterns from excluded_dirs.yaml."""
from __future__ import annotations

import functools
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Default config path: resolved relative to CWD at runtime.
# The file lives at the repo root alongside the scanner invocation.
_DEFAULT_CONFIG = Path("excluded_dirs.yaml")


@functools.lru_cache(maxsize=1)
def load_excluded_patterns(config_path: str = "") -> frozenset[str]:
    """Return the set of enabled excluded-directory patterns.

    Reads *config_path* (defaults to ``excluded_dirs.yaml`` in CWD).
    Returns an empty frozenset if the file does not exist (scanning proceeds normally).
    Result is cached for the lifetime of the process.
    """
    path = Path(config_path) if config_path else _DEFAULT_CONFIG
    if not path.is_file():
        logger.debug("excluded_dirs config not found at %s, no dirs excluded", path)
        return frozenset()
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        patterns: frozenset[str] = frozenset(
            r["pattern"]
            for r in data.get("rules", [])
            if r.get("enabled") and r.get("pattern")
        )
        logger.debug("Loaded %d excluded-dir patterns from %s", len(patterns), path)
        return patterns
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load excluded_dirs config %s: %s", path, exc)
        return frozenset()


def path_has_excluded_component(posix_rel: str, excluded: frozenset[str]) -> bool:
    """Return True if any path component of *posix_rel* is in *excluded*.

    Matches at any nesting level: ``a/node_modules/b.js`` and ``node_modules/a.js``
    both match pattern ``node_modules``.
    """
    if not excluded:
        return False
    return any(part in excluded for part in posix_rel.split("/"))
