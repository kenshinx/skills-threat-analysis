"""Tests for the file loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

from scanner.loader import detect_source, generate_id, load_skills


class TestLoader:
    def test_detect_source_clawhub(self):
        assert detect_source(Path("/data/clawhub/skill-1.md")) == "clawhub"

    def test_detect_source_smithery(self):
        assert detect_source(Path("/data/smithery/tools/skill.yaml")) == "smithery"

    def test_detect_source_unknown(self):
        assert detect_source(Path("/data/other/skill.md")) == "unknown"

    def test_generate_id(self):
        id1 = generate_id("clawhub", Path("/a/b.md"))
        id2 = generate_id("clawhub", Path("/a/c.md"))
        assert id1.startswith("clawhub-")
        assert id2.startswith("clawhub-")
        assert id1 != id2

    def test_load_skill_directory_with_entry(self):
        """A directory with SKILL.md should be loaded as one SkillFile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "my-skill"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text("# My Skill")
            refs = skill_dir / "references"
            refs.mkdir()
            (refs / "guide.md").write_text("# Guide content")
            (refs / "data.json").write_text('{"key": "value"}')
            (refs / "ignore.py").write_text("print('hi')")  # Not included

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# My Skill" in skills[0].content
            assert "Guide content" in skills[0].content
            assert "key" in skills[0].content
            assert "print" not in skills[0].content

    def test_load_multiple_skill_directories(self):
        """Each skill directory yields one SkillFile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["skill-a", "skill-b", "skill-c"]:
                d = Path(tmpdir) / name
                d.mkdir()
                (d / "SKILL.md").write_text(f"# {name}")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 3

    def test_fallback_flat_files(self):
        """Directories without SKILL.md fall back to scanning individual files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "skill1.md").write_text("# Skill 1")
            (Path(tmpdir) / "skill2.yaml").write_text("name: skill2")
            (Path(tmpdir) / "ignore.py").write_text("print('hi')")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 2
            assert all(s.content for s in skills)

    def test_load_skills_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            skills = list(load_skills(tmpdir))
            assert len(skills) == 0

    def test_load_skills_nonexistent_dir(self):
        skills = list(load_skills("/nonexistent/path"))
        assert len(skills) == 0
