"""Advanced detection passes ported from skill-scan-1.0.0 prompt_analyzer.

Implements six code-level checks that cannot be expressed as pure regex rules:

* PA-001  Invisible Unicode density analysis
* PA-002  Homoglyph (confusable) attack detection
* PA-003  Mixed-script anomaly detection
* PA-004  Markdown hidden-instruction extraction
* PA-005  Gradual escalation structure analysis
* PA-006  Encoded payload detection (Base64 / ROT13)
"""

from __future__ import annotations

import base64
import re

from scanner.models import RuleMatch, Severity

# ---------------------------------------------------------------------------
# Data tables (ported from skill-scan-1.0.0 prompt_analyzer.py)
# ---------------------------------------------------------------------------

INVISIBLE_CHARS: list[str] = [
    "\u200B",  # Zero-width space
    "\u200C",  # Zero-width non-joiner
    "\u200D",  # Zero-width joiner
    "\uFEFF",  # Byte order mark
    "\u00AD",  # Soft hyphen
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\u180E",  # Mongolian vowel separator
    "\u200E",  # Left-to-right mark
    "\u200F",  # Right-to-left mark
    "\u202A",  # Left-to-right embedding
    "\u202B",  # Right-to-left embedding
    "\u202C",  # Pop directional formatting
    "\u202D",  # Left-to-right override
    "\u202E",  # Right-to-left override
    "\u2066",  # Left-to-right isolate
    "\u2067",  # Right-to-left isolate
    "\u2068",  # First strong isolate
    "\u2069",  # Pop directional isolate
]

# Cyrillic / Greek characters that are visually identical to Latin letters.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0410": "A", "\u0412": "B", "\u0415": "E",
    "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0423": "Y", "\u0425": "X",
    # Greek
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i",
    "\u03ba": "k", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t",
    "\u03c5": "u", "\u03c7": "x",
}

SCRIPT_RANGES: dict[str, re.Pattern[str]] = {
    "latin":      re.compile(r"[\u0041-\u024F]"),
    "cyrillic":   re.compile(r"[\u0400-\u04FF]"),
    "greek":      re.compile(r"[\u0370-\u03FF]"),
    "arabic":     re.compile(r"[\u0600-\u06FF]"),
    "cjk":        re.compile(r"[\u4E00-\u9FFF\u3400-\u4DBF]"),
    "hangul":     re.compile(r"[\uAC00-\uD7AF]"),
    "devanagari": re.compile(r"[\u0900-\u097F]"),
}

# ROT13-encoded forms of suspicious injection keywords.
ROT13_INJECTIONS: list[str] = [
    "vtaber",          # ignore
    "flfgrz",          # system
    "bireevqr",        # override
    "vafgehpgvbaf",    # instructions
    "riny",            # eval
    "rknp",            # exec
]

# Emoji range – used to skip ZWJ (U+200D) inside emoji sequences.
_EMOJI_RANGE_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F900-\U0001F9FF]"
)

# Regex for extracting Base64-like blocks (≥40 chars).
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Markdown patterns for hidden-content extraction.
_MD_IMG_ALT_RE  = re.compile(r"!\[([^\]]{20,})\]\(")
_MD_COMMENT_RE  = re.compile(r"<!--([\s\S]*?)-->")
_MD_LINK_RE     = re.compile(r"\[([^\]]{20,})\]\([^)]+\)")
_MD_DATA_URI_RE = re.compile(r"\(data:[^)]+\)")

# Instruction-signal phrases used by _looks_like_instruction().
_INSTRUCTION_SIGNALS: list[str] = [
    "you must", "you should", "you will", "you are now",
    "ignore", "forget", "disregard", "override",
    "do not tell", "don't tell", "never tell", "never mention",
    "new instructions", "real instructions", "actual instructions",
    "system prompt", "execute", "send all", "share your",
    "api key", "credential", "token", "password", "secret",
    "immediately", "right now", "at once",
    "pretend", "act as", "role play", "simulate",
    "admin mode", "debug mode", "developer mode",
    "important:", "critical:", "urgent:",
]


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class AdvancedAnalyzer:
    """Code-level detection passes that complement the regex rule engine."""

    def scan(
        self,
        content: str,
        masked_ranges: list[tuple[int, int]],
    ) -> list[RuleMatch]:
        """Run all advanced passes and return :class:`RuleMatch` objects."""
        matches: list[RuleMatch] = []
        matches.extend(self._detect_invisible_unicode(content))
        matches.extend(self._detect_homoglyphs(content))
        matches.extend(self._detect_mixed_scripts(content))
        matches.extend(self._detect_markdown_injection(content, masked_ranges))
        matches.extend(self._detect_gradual_escalation(content))
        matches.extend(self._detect_encoded_payloads(content))
        return matches

    # -- PA-001: Invisible Unicode density ------------------------------------

    @staticmethod
    def _detect_invisible_unicode(content: str) -> list[RuleMatch]:
        findings: list[RuleMatch] = []
        count = 0
        first_pos = -1

        for char in INVISIBLE_CHARS:
            idx = content.find(char)
            while idx != -1:
                # Skip U+200D when it's part of an emoji ZWJ sequence.
                if char == "\u200D":
                    before = content[idx - 1] if idx > 0 else ""
                    after = content[idx + 1] if idx + 1 < len(content) else ""
                    if _EMOJI_RANGE_RE.match(before) or _EMOJI_RANGE_RE.match(after):
                        idx = content.find(char, idx + 1)
                        continue

                if first_pos == -1:
                    first_pos = idx
                count += 1
                idx = content.find(char, idx + 1)

        if count == 0:
            return findings

        # Determine severity by density.
        if count > 20:
            severity = Severity.CRITICAL
        elif count > 5:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        findings.append(RuleMatch(
            rule_id="PA-001",
            rule_name="invisible_unicode_density",
            severity=severity,
            matched_text=f"{count} invisible Unicode char(s)",
            position=(first_pos, first_pos + 1),
            pattern="(advanced) invisible char density",
        ))

        # Strip-and-rescan: if many invisible chars, check whether the cleaned
        # text reveals injection keywords that were hidden between visible text.
        if count > 5:
            char_set = set(INVISIBLE_CHARS)
            stripped = "".join(ch for ch in content if ch not in char_set)
            if _looks_like_instruction(stripped):
                findings.append(RuleMatch(
                    rule_id="PA-001",
                    rule_name="invisible_unicode_hidden_injection",
                    severity=Severity.CRITICAL,
                    matched_text="Injection keywords revealed after stripping invisible chars",
                    position=(first_pos, first_pos + 1),
                    pattern="(advanced) strip-and-rescan",
                ))

        return findings

    # -- PA-002: Homoglyph attack detection -----------------------------------

    @staticmethod
    def _detect_homoglyphs(content: str) -> list[RuleMatch]:
        found: list[dict] = []
        for i, char in enumerate(content):
            if char in HOMOGLYPHS:
                found.append({"char": char, "latin": HOMOGLYPHS[char], "index": i})

        if not found:
            return []

        # Build sample snippets (up to 5).
        samples: list[str] = []
        for f in found[:5]:
            start = max(0, f["index"] - 10)
            end = min(len(content), f["index"] + 10)
            snippet = content[start:end].replace("\n", " ").strip()
            samples.append(f'"{snippet}" ({f["char"]}\u2192{f["latin"]})')

        severity = Severity.HIGH if len(found) >= 3 else Severity.MEDIUM
        return [RuleMatch(
            rule_id="PA-002",
            rule_name="homoglyph_attack",
            severity=severity,
            matched_text=f"{len(found)} homoglyph(s): {', '.join(samples)}",
            position=(found[0]["index"], found[0]["index"] + 1),
            pattern="(advanced) homoglyph map",
        )]

    # -- PA-003: Mixed-script anomaly -----------------------------------------

    @staticmethod
    def _detect_mixed_scripts(content: str) -> list[RuleMatch]:
        detected: dict[str, int] = {}
        for name, regex in SCRIPT_RANGES.items():
            n = len(regex.findall(content))
            if n:
                detected[name] = n

        findings: list[RuleMatch] = []

        # Latin + Cyrillic mix with significant presence of both.
        if detected.get("latin", 0) > 5 and detected.get("cyrillic", 0) > 5:
            findings.append(RuleMatch(
                rule_id="PA-003",
                rule_name="mixed_scripts_latin_cyrillic",
                severity=Severity.HIGH,
                matched_text=(
                    f"Latin ({detected['latin']} chars) + "
                    f"Cyrillic ({detected['cyrillic']} chars)"
                ),
                position=(0, 1),
                pattern="(advanced) mixed scripts",
            ))

        # More than 3 distinct scripts is unusual.
        if len(detected) > 3:
            scripts = ", ".join(detected.keys())
            findings.append(RuleMatch(
                rule_id="PA-003",
                rule_name="mixed_scripts_multi",
                severity=Severity.MEDIUM,
                matched_text=f"{len(detected)} scripts: {scripts}",
                position=(0, 1),
                pattern="(advanced) mixed scripts",
            ))

        return findings

    # -- PA-004: Markdown hidden instructions ---------------------------------

    @staticmethod
    def _detect_markdown_injection(
        content: str,
        masked_ranges: list[tuple[int, int]],
    ) -> list[RuleMatch]:
        findings: list[RuleMatch] = []

        def _in_mask(start: int, end: int) -> bool:
            for rs, re_ in masked_ranges:
                if start >= rs and end <= re_:
                    return True
            return False

        # Image alt-text with instruction-like content.
        for m in _MD_IMG_ALT_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            alt_text = m.group(1)
            if _looks_like_instruction(alt_text):
                findings.append(RuleMatch(
                    rule_id="PA-004",
                    rule_name="markdown_hidden_instruction",
                    severity=Severity.CRITICAL,
                    matched_text=f"img alt: {alt_text[:80]}",
                    position=(m.start(), m.end()),
                    pattern="(advanced) markdown injection",
                ))

        # HTML comments containing instruction-like content.
        for m in _MD_COMMENT_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            comment = m.group(1).strip()
            if _looks_like_instruction(comment):
                findings.append(RuleMatch(
                    rule_id="PA-004",
                    rule_name="markdown_hidden_instruction",
                    severity=Severity.CRITICAL,
                    matched_text=f"comment: {comment[:80]}",
                    position=(m.start(), m.end()),
                    pattern="(advanced) markdown injection",
                ))

        # Link text with instruction-like content.
        for m in _MD_LINK_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            link_text = m.group(1)
            if _looks_like_instruction(link_text):
                findings.append(RuleMatch(
                    rule_id="PA-004",
                    rule_name="markdown_hidden_instruction",
                    severity=Severity.HIGH,
                    matched_text=f"link: {link_text[:80]}",
                    position=(m.start(), m.end()),
                    pattern="(advanced) markdown injection",
                ))

        # Data URIs embedded in markdown.
        for m in _MD_DATA_URI_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            findings.append(RuleMatch(
                rule_id="PA-004",
                rule_name="markdown_data_uri",
                severity=Severity.MEDIUM,
                matched_text=m.group(0)[:80],
                position=(m.start(), m.end()),
                pattern="(advanced) markdown data URI",
            ))

        return findings

    # -- PA-005: Gradual escalation -------------------------------------------

    @staticmethod
    def _detect_gradual_escalation(content: str) -> list[RuleMatch]:
        paragraphs = re.split(r"\n\s*\n", content)
        if len(paragraphs) < 3:
            return []

        has_early_innocent = False
        late_aggressive_count = 0

        for i, para in enumerate(paragraphs):
            position = i / len(paragraphs)
            is_instr = _looks_like_instruction(para)

            if position < 0.3 and not is_instr:
                has_early_innocent = True
            if position > 0.7 and is_instr:
                late_aggressive_count += 1

        if has_early_innocent and late_aggressive_count >= 2:
            return [RuleMatch(
                rule_id="PA-005",
                rule_name="gradual_escalation",
                severity=Severity.MEDIUM,
                matched_text="Early innocent content followed by late instruction-like content",
                position=(0, 1),
                pattern="(advanced) gradual escalation",
            )]

        return []

    # -- PA-006: Encoded payloads (Base64 / ROT13) ----------------------------

    @staticmethod
    def _detect_encoded_payloads(content: str) -> list[RuleMatch]:
        findings: list[RuleMatch] = []

        # Base64 blocks.
        for m in _BASE64_RE.finditer(content):
            try:
                decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="replace")
                printable = "".join(c for c in decoded if 32 <= ord(c) <= 126 or c == "\n")
                if len(printable) > len(decoded) * 0.7 and _looks_like_instruction(decoded):
                    findings.append(RuleMatch(
                        rule_id="PA-006",
                        rule_name="encoded_payload_base64",
                        severity=Severity.CRITICAL,
                        matched_text=f"Base64 decodes to: {printable[:80]}",
                        position=(m.start(), m.end()),
                        pattern="(advanced) base64 decode",
                    ))
            except Exception:
                pass

        # ROT13-encoded injection terms.
        lower = content.lower()
        for encoded in ROT13_INJECTIONS:
            idx = lower.find(encoded)
            if idx != -1:
                decoded = _rot13(encoded)
                findings.append(RuleMatch(
                    rule_id="PA-006",
                    rule_name="encoded_payload_rot13",
                    severity=Severity.MEDIUM,
                    matched_text=f'ROT13 "{encoded}" -> "{decoded}"',
                    position=(idx, idx + len(encoded)),
                    pattern="(advanced) ROT13 lookup",
                ))

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _looks_like_instruction(text: str) -> bool:
    """Return True if *text* contains instruction-like signal phrases."""
    if not text or len(text) < 10:
        return False
    lower = text.lower()
    return any(signal in lower for signal in _INSTRUCTION_SIGNALS)


def _rot13(s: str) -> str:
    """Decode a ROT13-encoded string."""
    result: list[str] = []
    for c in s:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)
