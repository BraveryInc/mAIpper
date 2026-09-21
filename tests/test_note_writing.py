#!/usr/bin/env python3
"""Regression tests for host/scan note writing.

Covers the failure classes found in the v0.15 audit. All of these were live
bugs; each test fails against the v0.14 code.

  1. Section writes must not depend on reconstructing the old section as an
     exact string -- a blank line after the header silently no-opped the write
     while the checkbox still flipped to [/] (done).
  2. LLM output containing backslashes (DOMAIN\\user, C:\\Windows, UNC paths,
     regex group refs) must be inserted verbatim, not parsed as an re.sub
     replacement template, which raised re.error and lost the analysis.
  3. Host-note writers must carry forward host-level frontmatter they do not
     own -- notably `ips`, which only /merge writes, and the loot counters.
  4. Operator-authored content (## Operator Notes, ## Access) must survive
     every writer.

Run standalone:   python tests/test_note_writing.py
Run under pytest: pytest tests/test_note_writing.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402

m = fixtures.load_maipper("maipper_under_test")

BS = fixtures.BS
BACKSLASH_PAYLOADS = fixtures.BACKSLASH_PAYLOADS
PRESERVED = fixtures.PRESERVED


def _seeded_host(tmp: Path):
    return fixtures.seed_host_note(tmp)


# --------------------------------------------------------------------------
# 1. section writes survive whitespace drift
# --------------------------------------------------------------------------

def test_deep_dive_survives_blank_line_after_header():
    """A blank line after '## Analysis' used to swallow the result silently."""
    shapes = {
        "tight": "## Analysis\n> [!info]- Analysis: SMB\n> earlier\n",
        "blank_after_header": "## Analysis\n\n> [!info]- Analysis: SMB\n> earlier\n",
        "trailing_blank": "## Analysis\n> [!info]- Analysis: SMB\n> earlier\n\n",
        "absent": "",
    }
    template = (
        "---\nip: 10.10.10.5\n---\n\n## Open Ports\n"
        "- [x] Investigate: LDAP (tcp/389)\n\n{section}\n"
        "## Scan References\n- [[Scans/x|x]]\n\n## Operator Notes\nkeep me\n"
    )
    for name, section in shapes.items():
        with tempfile.TemporaryDirectory() as td:
            note = Path(td) / "h.md"
            note.write_text(template.format(section=section), encoding="utf-8")
            m._write_deep_dive_result(note, "LDAP (tcp/389)", "FRESH ANALYSIS")
            out = note.read_text(encoding="utf-8")
            assert "FRESH ANALYSIS" in out, f"{name}: new analysis dropped"
            assert "- [/] Investigate: LDAP (tcp/389)" in out, f"{name}: checkbox not marked"
            assert "keep me" in out, f"{name}: operator notes lost"
            if section:
                assert "earlier" in out, f"{name}: prior deep dive lost"


def test_scan_note_analysis_created_when_section_absent():
    """Writing analysis into a note with no ## Analysis used to be a no-op."""
    with tempfile.TemporaryDirectory() as td:
        note = Path(td) / "s.md"
        note.write_text("# S\n\n- [x] Analyze: Nmap\n\n## Operator Notes\nn\n",
                        encoding="utf-8")
        m._update_scan_note_analysis(note, "BODY", "mdl", "Nmap", ["w1", "w2"])
        out = note.read_text(encoding="utf-8")
        assert "## Analysis" in out and "BODY" in out
        assert "## Validation Warnings" in out and "- w1" in out
        assert "- [/] Analyze: Nmap" in out


def test_fenced_heading_does_not_truncate_section():
    """A '## ' line inside a code fence must not end the section."""
    with tempfile.TemporaryDirectory() as td:
        note = Path(td) / "h.md"
        note.write_text(
            "---\nip: 10.10.10.9\n---\n\n## Deep Dive\n\n```\n## not a heading\n```\n\n"
            "## Operator Notes\nkeep\n",
            encoding="utf-8",
        )
        m._write_cross_source_result(note, "REPLACED")
        out = note.read_text(encoding="utf-8")
        assert "REPLACED" in out
        assert "keep" in out and "## Operator Notes" in out


# --------------------------------------------------------------------------
# 2. backslashes in LLM output
# --------------------------------------------------------------------------

def test_cross_source_accepts_backslashes():
    """DOMAIN\\user, Windows paths and UNC paths used to raise re.error."""
    for payload in BACKSLASH_PAYLOADS:
        with tempfile.TemporaryDirectory() as td:
            note = Path(td) / "h.md"
            note.write_text(
                "---\nip: 10.10.10.9\n---\n\n## Deep Dive\n\nold\n\n## Operator Notes\nn\n",
                encoding="utf-8",
            )
            m._write_cross_source_result(note, payload)
            assert payload in note.read_text(encoding="utf-8"), payload


def test_scan_note_accepts_backslashes():
    for payload in BACKSLASH_PAYLOADS:
        with tempfile.TemporaryDirectory() as td:
            note = Path(td) / "s.md"
            note.write_text(
                "# S\n\n- [x] Analyze: Nmap\n\n## Analysis\n\nold\n\n"
                "## Operator Notes\nn\n",
                encoding="utf-8",
            )
            m._update_scan_note_analysis(note, payload, "mdl", "Nmap")
            out = note.read_text(encoding="utf-8")
            assert payload in out, payload
            assert "- [/] Analyze: Nmap" in out


def test_deep_dive_accepts_backslash_topic():
    """Operator-authored checkbox topics may contain backslashes."""
    topic = "SMB share " + BS * 2 + "host" + BS + "IPC$"
    with tempfile.TemporaryDirectory() as td:
        note = Path(td) / "h.md"
        note.write_text(
            "---\nip: 10.10.10.9\n---\n\n## Open Ports\n- [x] Investigate: " + topic +
            "\n\n## Operator Notes\nn\n",
            encoding="utf-8",
        )
        m._write_deep_dive_result(note, topic, "RESULT")
        out = note.read_text(encoding="utf-8")
        assert "RESULT" in out
        assert "- [/] Investigate: " + topic in out


# --------------------------------------------------------------------------
# 3 + 4. frontmatter and operator content survive every writer
# --------------------------------------------------------------------------

PRESERVED = {
    "ips": ["172.16.1.100", "192.168.50.5"],
    "domain": "CORP",
    "nessus_max_severity": 4,
    "autorecon_tools_run": 15,
    "loot_file_count": 3,
    "loot_credential_count": 7,
    "loot_hash_count": 2,
}


def _assert_preserved(note: Path, owned: tuple[str, ...] = ()) -> None:
    """Assert preserved frontmatter and operator content survived a write.

    *owned* names keys the writer legitimately recomputes.
    """
    text = note.read_text(encoding="utf-8")
    fm, _ = m.read_frontmatter(text)
    for key, expected in PRESERVED.items():
        if key in owned:
            continue
        assert fm.get(key) == expected, f"frontmatter {key}: {fm.get(key)!r} != {expected!r}"
    assert fm.get("status") == "exploited", "operator status was reset"
    for marker in ("## Access", "psexec", "## NXC Enumeration", "operator wrote this"):
        assert marker in text, f"lost body content: {marker}"


def test_nmap_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._write_host_note(hosts_dir, fixtures.NMAP_HOST, "New - Nmap", "New", "Nmap")
        _assert_preserved(note)


def test_nessus_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_nessus(
            hosts_dir, "10.10.10.5", "dc01.corp.local", fixtures.NESSUS_FINDINGS, "New - Nessus"
        )
        _assert_preserved(note)


def test_burp_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_burp(
            hosts_dir, "10.10.10.5", "http://dc01.corp.local/", fixtures.BURP_ISSUES, "New - Burp"
        )
        _assert_preserved(note)


def test_autorecon_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_autorecon(
            hosts_dir, "10.10.10.5", "dc01.corp.local", fixtures.AUTORECON_TARGET, "New - AutoRecon"
        )
        _assert_preserved(note, owned=("autorecon_tools_run",))


def test_loot_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_loot(
            hosts_dir, "10.10.10.5", "dc01.corp.local", fixtures.LOOT_FILES, "Loot"
        )
        _assert_preserved(
            note, owned=("loot_file_count", "loot_credential_count", "loot_hash_count")
        )


def test_preserved_keys_constant_covers_known_host_level_fields():
    """Guard against a new host-level field being added without preservation."""
    for key in ("ips", "domain", "nessus_max_severity", "autorecon_tools_run",
                "loot_file_count", "loot_credential_count", "loot_hash_count"):
        assert key in m.PRESERVED_FM_KEYS, f"{key} missing from PRESERVED_FM_KEYS"


# --------------------------------------------------------------------------
# standalone runner (no pytest required)
# --------------------------------------------------------------------------

def _main() -> int:
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            print(f"  FAIL  {name}: {exc}")
            failed.append(name)
        except Exception as exc:  # noqa: BLE001 - surface unexpected errors as failures
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
            failed.append(name)
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
