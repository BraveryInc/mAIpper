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

import importlib.util
import tempfile
from pathlib import Path

BS = chr(92)  # backslash, kept out of literals so this file stays escape-free

_MODULE_PATH = Path(__file__).resolve().parent.parent / "mAIpper.py"


def _load_maipper():
    spec = importlib.util.spec_from_file_location("maipper_under_test", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = _load_maipper()


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

HOST_NOTE = """---
ip: 10.10.10.5
ips: ["172.16.1.100", "192.168.50.5"]
hostnames: ["dc01.corp.local"]
status: exploited
tags: ["smb", "ldap"]
sources: ["Prior - Nmap"]
domain: CORP
nessus_max_severity: 4
autorecon_tools_run: 15
loot_file_count: 3
loot_credential_count: 7
loot_hash_count: 2
---
**State:** up
**IP:** 10.10.10.5

## Open Ports
- **445/tcp** - microsoft-ds
  - [ ] Investigate: SMB (tcp/445)

## Access
| User | Priv | Method |
| --- | --- | --- |
| adm | SYSTEM | psexec |

## NXC Enumeration
signing: false

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this
"""

NMAP_HOST = {
    "state": "up",
    "addresses": [{"addr": "10.10.10.5", "addrtype": "ipv4"}],
    "hostnames": [{"name": "dc01.corp.local", "type": "PTR"}],
    "open_ports": [
        {
            "protocol": "tcp",
            "port": 445,
            "service": {"name": "microsoft-ds", "product": "", "version": "",
                        "extrainfo": "", "tunnel": ""},
            "scripts": [],
        }
    ],
}

NESSUS_FINDING = {
    "plugin_id": "12345", "plugin_name": "SMB Signing Disabled",
    "severity_int": 3, "port": 445, "protocol": "tcp",
    "description": "d", "solution": "s", "cves": [],
    "cvss_base": "", "cvss3_base": "", "plugin_output": "",
}

BURP_ISSUE = {
    "name": "XSS", "path": "/a", "location": "/a", "severity": "High",
    "confidence": "Certain", "issue_detail": "d", "issue_background": "b",
    "remediation_detail": "r", "remediation_background": "rb",
}

AUTORECON_TARGET = {
    "target": "10.10.10.5", "ip": "10.10.10.5", "hostname": "dc01.corp.local",
    "tool_results": {}, "commands_log": "", "manual_commands": "",
    "nmap_xml_files": [],
    "summary": {"total_tools_run": 9, "tools_with_findings": 0, "technologies": [],
                "writable_shares": [], "null_session": False, "users_found": [],
                "weak_tls": [], "community_strings": []},
}

LOOT_FILE = {
    "filename": "c.txt", "filepath": "/x/c.txt", "size_bytes": 10,
    "credentials": [], "hashes": [], "file_listings": [], "network_refs": [],
    "standalone_usernames": [], "raw_preview": "", "category": "notes",
}

# LLM output that used to crash re.sub as a replacement template
BACKSLASH_PAYLOADS = [
    "Authenticate as DOMAIN" + BS + "Administrator.",
    "Mount " + BS * 2 + "10.10.10.5" + BS + "C$ with smbclient.",
    "Stage the payload in C:" + BS + "Windows" + BS + "Temp.",
    "The pattern (a)" + BS + "1 matched twice.",
    "Check the " + BS + "group directory.",
]


def _seeded_host(tmp: Path) -> tuple[Path, Path]:
    hosts_dir = tmp / "Hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    note = hosts_dir / "10.10.10.5.md"
    note.write_text(HOST_NOTE, encoding="utf-8")
    return hosts_dir, note


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
        m._write_host_note(hosts_dir, NMAP_HOST, "New - Nmap", "New", "Nmap")
        _assert_preserved(note)


def test_nessus_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_nessus(
            hosts_dir, "10.10.10.5", "dc01.corp.local", [NESSUS_FINDING], "New - Nessus"
        )
        _assert_preserved(note)


def test_burp_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_burp(
            hosts_dir, "10.10.10.5", "http://dc01.corp.local/", [BURP_ISSUE], "New - Burp"
        )
        _assert_preserved(note)


def test_autorecon_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_autorecon(
            hosts_dir, "10.10.10.5", "dc01.corp.local", AUTORECON_TARGET, "New - AutoRecon"
        )
        _assert_preserved(note, owned=("autorecon_tools_run",))


def test_loot_writer_preserves_host_frontmatter():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        m._update_host_note_loot(
            hosts_dir, "10.10.10.5", "dc01.corp.local", [LOOT_FILE], "Loot"
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
