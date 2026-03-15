"""Tests for the file loader."""

from __future__ import annotations

import hashlib
import re
import tempfile
import zipfile
from pathlib import Path

from scanner.loader import detect_source, generate_id, load_skills

_HEX_MD5 = re.compile(r"^[0-9a-f]{32}$")
_HEX_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class TestLoader:
    def test_detect_source_clawhub(self):
        assert detect_source(Path("/data/clawhub/skill-1.md")) == "clawhub"

    def test_detect_source_clawhub_data(self):
        """clawhub_data directory should match as clawhub source."""
        assert detect_source(Path("/Downloads/clawhub_data/author/skill")) == "clawhub"

    def test_detect_source_smithery(self):
        assert detect_source(Path("/data/smithery/tools/skill.yaml")) == "smithery"

    def test_detect_source_unknown(self):
        assert detect_source(Path("/data/other/skill.md")) == "unknown"

    def test_generate_id(self):
        id1 = generate_id(Path("/a/b.md"))
        id2 = generate_id(Path("/a/c.md"))
        assert id1.startswith("b-")
        assert id2.startswith("c-")
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
            (refs / "helper.py").write_text("print('hi')")  # .py now included
            (refs / "ignore.csv").write_text("a,b,c")  # Not included

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# My Skill" in skills[0].content
            assert "Guide content" in skills[0].content
            assert "key" in skills[0].content
            assert "print" in skills[0].content  # .py is supported
            assert "a,b,c" not in skills[0].content  # .csv is not
            assert skills[0].name == "my-skill"
            assert skills[0].skill_dir == str(skill_dir)
            # file hashes cover all files (including .csv)
            assert "SKILL.md" in skills[0].file_md5s
            assert "references/guide.md" in skills[0].file_md5s
            assert "references/data.json" in skills[0].file_md5s
            assert "references/helper.py" in skills[0].file_md5s
            assert "references/ignore.csv" in skills[0].file_md5s
            for v in skills[0].file_md5s.values():
                assert _HEX_MD5.match(v)
            for v in skills[0].file_sha1s.values():
                assert _HEX_SHA1.match(v)
            assert skills[0].package_md5 == ""
            assert skills[0].package_sha1 == ""

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
            (Path(tmpdir) / "helper.py").write_text("print('hi')")
            (Path(tmpdir) / "ignore.csv").write_text("a,b,c")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 3  # .md + .yaml + .py
            assert all(s.content for s in skills)
            by_name = {s.name: s for s in skills}
            assert "skill1" in by_name
            assert by_name["skill1"].skill_dir == tmpdir
            assert "skill1.md" in by_name["skill1"].file_md5s
            assert _HEX_MD5.match(by_name["skill1"].file_md5s["skill1.md"])

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
            assert skills[0].name == "my-skill"
            assert skills[0].skill_dir == str(skill_dir)
            # zip-based: file hashes from extracted content
            assert "SKILL.md" in skills[0].file_md5s
            assert "references/guide.md" in skills[0].file_md5s
            # zip-based: package hash from zip file
            assert _HEX_MD5.match(skills[0].package_md5)
            assert _HEX_SHA1.match(skills[0].package_sha1)
            expected_pkg_md5 = hashlib.md5(zip_path.read_bytes()).hexdigest()
            assert skills[0].package_md5 == expected_pkg_md5

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

    def test_load_skill_extension(self):
        """A .skill file is equivalent to .zip per spec §3.1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "my-skill"
            skill_dir.mkdir()
            skill_path = skill_dir / "my-skill.skill"
            with zipfile.ZipFile(skill_path, "w") as zf:
                zf.writestr("SKILL.md", "# Skill Extension Test")
                zf.writestr("lib/helper.py", "def run(): pass")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# Skill Extension Test" in skills[0].content
            assert "SKILL.md" in skills[0].file_md5s
            assert "lib/helper.py" in skills[0].file_md5s
            assert _HEX_MD5.match(skills[0].package_md5)

    def test_normalize_zip_flat_format_not_unwrapped(self):
        """Flat zip (SKILL.md at root with other files) must not be unwrapped (spec §4.1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "flat-skill"
            skill_dir.mkdir()
            with zipfile.ZipFile(skill_dir / "flat.zip", "w") as zf:
                zf.writestr("SKILL.md", "# Flat Format")
                zf.writestr("run.sh", "echo hi")
                zf.writestr("scripts/main.py", "print('main')")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "# Flat Format" in skills[0].content
            # File keys must be relative to root (not inside a wrapper dir)
            assert "SKILL.md" in skills[0].file_md5s
            assert "run.sh" in skills[0].file_md5s
            assert "scripts/main.py" in skills[0].file_md5s

    def test_normalize_zip_top_level_files_prevent_unwrap(self):
        """Zip with top-level files alongside subdirs stays at root (spec §4.1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "mixed-skill"
            skill_dir.mkdir()
            with zipfile.ZipFile(skill_dir / "mixed.zip", "w") as zf:
                # SKILL.md at root + inner dir: top_files=[SKILL.md], so no unwrap
                zf.writestr("SKILL.md", "# Mixed Root")
                zf.writestr("inner/extra.py", "pass")

            skills = list(load_skills(tmpdir))
            assert len(skills) == 1
            assert "SKILL.md" in skills[0].file_md5s
            assert "inner/extra.py" in skills[0].file_md5s
