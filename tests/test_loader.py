"""Tests for the file loader."""

from __future__ import annotations

import tempfile
import zipfile
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

    def test_load_skill_from_zip(self):
        """A directory with a .zip file containing SKILL.md should be loaded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "my-skill"
            skill_dir.mkdir()
            # Create a zip with SKILL.md and a reference file
            zip_path = skill_dir / "my-skill.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("SKILL.md", "# Zipped Skill\nDo something useful.")
                zf.writestr("references/guide.md", "# Reference guide")
            # detail.json should be ignored
            (skill_dir / "detail.json").write_text('{"id": 123}')

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# Zipped Skill" in skills[0].content
            assert "Reference guide" in skills[0].content
            assert "detail.json" not in skills[0].content

    def test_load_zip_clawhub_layout(self):
        """Clawhub layout: <root>/<author>/<skill-name>/<skill>.zip."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            author_dir = root / "someauthor"
            skill_dir = author_dir / "cool-tool"
            skill_dir.mkdir(parents=True)
            with zipfile.ZipFile(skill_dir / "cool-tool.zip", "w") as zf:
                zf.writestr("SKILL.md", "# Cool Tool")
                zf.writestr("scripts/run.md", "run instructions")
            (skill_dir / "detail.json").write_text("{}")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# Cool Tool" in skills[0].content
            assert "run instructions" in skills[0].content

    def test_load_zip_with_wrapper_directory(self):
        """Zip that contains a wrapper directory around skill files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "wrapped-skill"
            skill_dir.mkdir()
            with zipfile.ZipFile(skill_dir / "wrapped.zip", "w") as zf:
                zf.writestr("inner/SKILL.md", "# Wrapped")
                zf.writestr("inner/assets/notes.txt", "extra notes")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# Wrapped" in skills[0].content
            assert "extra notes" in skills[0].content

    def test_load_zip_bad_zip_skipped(self):
        """A corrupt zip file should be skipped without crashing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "bad-skill"
            skill_dir.mkdir()
            (skill_dir / "bad.zip").write_bytes(b"not a zip file")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 0

    def test_load_zip_no_entry_file_skipped(self):
        """A zip without SKILL.md should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "no-entry"
            skill_dir.mkdir()
            with zipfile.ZipFile(skill_dir / "stuff.zip", "w") as zf:
                zf.writestr("readme.md", "just a readme")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 0
