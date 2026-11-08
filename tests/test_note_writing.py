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

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402

m = fixtures.load_maipper("maipper_under_test")
m._force_utf8_stdio()  # some code paths print arrows/unicode; the test
                       # harness never goes through main(), which is the only
                       # place that normally reconfigures stdio for Windows

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
    "critical_flags": ["Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) (CVE-2017-0143) - tcp/445"],
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
    for marker in ("## Access", "psexec", "## NXC Enumeration", "operator wrote this",
                   "## Critical Findings", "smb-vuln-ms17-010"):
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
                "loot_file_count", "loot_credential_count", "loot_hash_count",
                "critical_flags"):
        assert key in m.PRESERVED_FM_KEYS, f"{key} missing from PRESERVED_FM_KEYS"


# --------------------------------------------------------------------------
# 5. confirmed Nmap NSE vulnerabilities (e.g. MS17-010) are surfaced, not
#    left to LLM guesswork -- reported gap: EternalBlue was only ever
#    mentioned buried in a collapsed LLM callout, never as a hard fact.
# --------------------------------------------------------------------------

def test_extract_critical_nse_findings_reads_hostscript_vuln_state():
    findings = m._extract_critical_nse_findings(fixtures.NMAP_HOST_MS17_010)
    assert len(findings) == 1
    f = findings[0]
    assert f["script_id"] == "smb-vuln-ms17-010"
    assert "ms17-010" in f["title"].lower()
    assert f["cves"] == ["CVE-2017-0143"]
    assert f["risk_factor"] == "HIGH"
    assert f["port_label"] == ""  # hostscript, not tied to a specific port


def test_nmap_writer_surfaces_critical_findings_on_fresh_note():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir = Path(td) / "Hosts"
        hosts_dir.mkdir()
        m._write_host_note(hosts_dir, fixtures.NMAP_HOST_MS17_010, "New - Nmap", "New", "Nmap")
        note = hosts_dir / "dc01.corp.local.md"
        text = note.read_text(encoding="utf-8")
        fm, _ = m.read_frontmatter(text)
        assert "## Critical Findings" in text
        assert "smb-vuln-ms17-010" in text
        assert fm.get("critical_flags"), "critical_flags frontmatter not set"
        assert "CVE-2017-0143" in fm["critical_flags"][0]


def test_nmap_writer_merges_critical_findings_across_rescans():
    """A later, narrower re-scan (no vuln scripts) must not drop an earlier
    confirmed finding -- critical findings accumulate like open ports do."""
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))  # already has an MS17-010 finding
        plain_rescan = dict(fixtures.NMAP_HOST_MS17_010)
        plain_rescan["host_scripts"] = []  # this scan didn't run vuln scripts
        m._write_host_note(hosts_dir, plain_rescan, "Rescan - Nmap", "Rescan", "Nmap")
        text = note.read_text(encoding="utf-8")
        fm, _ = m.read_frontmatter(text)
        assert "smb-vuln-ms17-010" in text, "prior confirmed finding was dropped on re-scan"
        assert fm.get("critical_flags"), "critical_flags dropped on re-scan"


def test_loot_credentials_page_preserves_orphan_rows_without_backing_file():
    """A credential added via Injestor (kiwi paste, LSA secret, +cred -- no
    scans/loot/ file behind it) must survive the next routine loot-dir
    rescan. _write_loot_credentials_page used to rebuild the whole page from
    parse_loot_dir's output alone, so a normal re-run silently deleted any
    row it couldn't re-derive from a file on disk."""
    with tempfile.TemporaryDirectory() as td:
        loot_dir = Path(td) / "Loot"
        loot_dir.mkdir()
        creds_path = loot_dir / "Credentials.md"
        creds_path.write_text(
            "# Credentials & Users\n\n_Last updated: x_\n\n**Total credential entries:** 1\n\n"
            "## Campaign-Level\n\n"
            "| Username | Password | Hash | Hash Type | Source | Notes |\n"
            "|----------|----------|------|-----------|--------|-------|\n"
            "| `LSA Secret: DefaultPassword` | `hunter2` | — | — | LSA Secrets Dump | LSA secret |\n\n"
            "### Operator Notes\n_Note which hosts/services these credentials work on._\n",
            encoding="utf-8",
        )
        loot_data = {
            "parsed_at": "2026-01-01T00:00:00",
            "host_loot": {},
            "campaign_loot": [],
            "summary": {"total_credentials": 0},
        }
        m._write_loot_credentials_page(loot_dir, loot_data, {}, {})
        out = creds_path.read_text(encoding="utf-8")
        assert "LSA Secret: DefaultPassword" in out, "orphan credential row was dropped on rescan"
        assert "**Total credential entries:** 1" in out


def test_priority_targets_fallback_ranks_critical_flags_first():
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        hosts_dir = vault / "Hosts"
        hosts_dir.mkdir()
        # A host with many open ports but nothing confirmed.
        (hosts_dir / "busy.md").write_text(
            "---\nip: 10.10.10.9\nhostnames: []\ntags: [smb, rdp, winrm]\n---\n\n"
            "## Open Ports\n" + "\n".join(f"- **{p}/tcp** - svc" for p in range(10)) + "\n",
            encoding="utf-8",
        )
        # A host with a confirmed critical NSE finding but fewer ports.
        (hosts_dir / "dc.md").write_text(
            "---\nip: 10.10.10.5\nhostnames: []\ntags: [smb]\n"
            "critical_flags: [\"MS17-010 (EternalBlue) (CVE-2017-0143) - tcp/445\"]\n---\n\n"
            "## Open Ports\n- **445/tcp** - microsoft-ds\n",
            encoding="utf-8",
        )
        text = m._build_priority_targets_fallback(vault)
        dc_pos = text.find("10.10.10.5")
        busy_pos = text.find("10.10.10.9")
        assert dc_pos != -1 and busy_pos != -1
        assert dc_pos < busy_pos, "confirmed-vulnerable host must rank above a merely busy host"
        assert "CONFIRMED" in text


# --------------------------------------------------------------------------
# 6. explicit Injestor credential syntax: host-first phrasing, hash:password
#    values, and the templated ## Notes / ## Tool Output fast-path that used
#    to silently drop a short, precise credential line.
# --------------------------------------------------------------------------

def test_split_cred_value_separates_hash_from_cracked_password():
    pw, cred_type, note = m._split_cred_value("aad3b435b51404eeaad3b435b51404ee:CrackedPassword123")
    assert pw == "aad3b435b51404eeaad3b435b51404ee"
    assert cred_type == "NTLM_hash"
    assert "CrackedPassword123" in note


def test_split_cred_value_leaves_plain_password_intact():
    pw, cred_type, note = m._split_cred_value("hunter2")
    assert pw == "hunter2"
    assert cred_type == "cleartext"
    assert note == ""


def test_parse_injestor_creds_host_first_phrasing():
    """'for HOST user:pass' (host before the credential) -- the natural way
    to write "I cracked a password for this host" -- used to not match any
    supported pattern (only 'user:pass on HOST' was recognised)."""
    creds = m._parse_injestor_creds_with_host(
        "for CORP-WS03 administrator:aad3b435b51404eeaad3b435b51404ee:CrackedPassword123"
    )
    assert len(creds) == 1
    c = creds[0]
    assert c["username"] == "administrator"
    assert c["host"] == "CORP-WS03"
    assert c["password"] == "aad3b435b51404eeaad3b435b51404ee"
    assert c["cred_type"] == "NTLM_hash"
    assert "CrackedPassword123" in c["notes"]


def test_injestor_notes_explicit_credential_line_reaches_credentials_md():
    """A short, explicit 'for HOST user:hash:password' line pasted into the
    templated ## Notes section used to vanish with no feedback: templated
    Notes only ever tried NXC/kiwi detection, then gated everything else
    behind an 8-non-IP-word threshold a single credential line never reaches."""
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        hosts_dir = vault / "Hosts"
        hosts_dir.mkdir()
        (hosts_dir / "CORP-WS03.md").write_text(
            "---\nip: 10.10.10.5\nhostnames: []\ntags: []\n---\n\n"
            "## Open Ports\n- **445/tcp** - smb\n",
            encoding="utf-8",
        )
        injestor_text = m._INJESTOR_TEMPLATE.replace(
            "## Notes\n\n",
            "## Notes\n\nfor CORP-WS03 administrator:aad3b435b51404eeaad3b435b51404ee:CrackedPassword123\n\n",
        )
        (vault / "Injestor.md").write_text(injestor_text, encoding="utf-8")

        result = m._process_injestor(vault)
        assert result is not None, "Injestor processing found nothing"
        creds = result["discovered_creds"]
        assert any(c["username"] == "administrator" and c["host"] == "CORP-WS03" for c in creds), creds

        creds_md = (vault / "Loot" / "Credentials.md").read_text(encoding="utf-8")
        assert "CORP-WS03" in creds_md
        assert "administrator" in creds_md
        assert "CrackedPassword123" in creds_md

        # _link_injestor_creds_to_host_note used to crash with NameError
        # (called split_frontmatter(), which doesn't exist) every time a
        # discovered credential had a host attached -- i.e. every time host
        # attribution actually worked. Confirm the host note's ## Loot
        # section was updated, not just that nothing raised.
        host_note_text = (hosts_dir / "CORP-WS03.md").read_text(encoding="utf-8")
        assert "## Loot" in host_note_text
        assert "ip: 10.10.10.5" in host_note_text, "frontmatter was lost or corrupted"


# --------------------------------------------------------------------------
# 7. operator notes guide a targeted credential re-extraction pass on
#    Misc/Injestor scan notes, and the cred_type naming mismatch between
#    _llm_extract_tool_output/_parse_pending_review_row (bare "NTLM", "SHA1")
#    and _append_injestor_to_credentials_md (suffix "NTLM_hash", "hash")
#    that mislabeled hashes as passwords.
# --------------------------------------------------------------------------

def test_cred_type_is_hash_recognises_both_naming_conventions():
    assert m._cred_type_is_hash("NTLM_hash")
    assert m._cred_type_is_hash("hash")
    assert m._cred_type_is_hash("NTLM")
    assert m._cred_type_is_hash("SHA1")
    assert m._cred_type_is_hash("bcrypt")
    assert not m._cred_type_is_hash("cleartext")
    assert not m._cred_type_is_hash("plaintext")
    assert not m._cred_type_is_hash("")


def test_normalize_llm_extracted_cred_keeps_hash_primary():
    normalized = m._normalize_llm_extracted_cred({
        "username": "administrator", "password": "CrackedPw123",
        "hash": "aad3b435b51404eeaad3b435b51404ee", "hash_type": "NTLM",
        "host": "CORP-WS03", "notes": "",
    })
    assert normalized["password"] == "aad3b435b51404eeaad3b435b51404ee"
    assert normalized["cred_type"] == "NTLM"
    assert "CrackedPw123" in normalized["notes"]


def test_normalize_llm_extracted_cred_plain_password():
    normalized = m._normalize_llm_extracted_cred({
        "username": "svc_ldap", "password": "Summer2026!",
        "hash": "", "hash_type": "", "host": "", "notes": "",
    })
    assert normalized["password"] == "Summer2026!"
    assert normalized["cred_type"] == "cleartext"
    assert normalized["host"] is None


def test_operator_notes_guide_misc_reanalysis_credential_extraction():
    """A correction written in ## Operator Notes on a Misc/Injestor scan
    note (e.g. "it missed the cleartext password in that LDAP dump") must
    feed into a targeted re-extraction pass and actually reach
    Loot/Credentials.md -- not just get echoed back as prose in ## Analysis."""
    orig_ollama_chat = m.ollama_chat
    orig_llm_extract = m._llm_extract_tool_output
    try:
        with tempfile.TemporaryDirectory() as td:
            vault = Path(td)
            hosts_dir = vault / "Hosts"
            hosts_dir.mkdir()
            (hosts_dir / "CORP-DC01.md").write_text(
                "---\nip: 10.10.10.5\nhostnames: []\ntags: []\n---\n\n## Open Ports\n",
                encoding="utf-8",
            )
            scans_dir = vault / "Scans"
            scans_dir.mkdir()
            scan_path = scans_dir / "LDAP Output - 20260101-000000.md"
            scan_path.write_text(
                "# LDAP Output - 20260101-000000\n\n"
                "- **Source:** Injestor\n"
                "- **Detected tool:** ldapsearch\n"
                "- **Analysis level:** standard\n\n"
                "- [x] Analyze: Misc\n\n## Analysis\n\n_No AI analysis generated._\n\n"
                "## Tool Output\n\n<details>\n<summary>Click to expand</summary>\n\n"
                "```\n# comment: backup pw is Summer2026!\ndn: cn=svc_ldap\n```\n\n</details>\n\n"
                "## Operator Notes\n\nit missed the cleartext password in the comment "
                "from that ldap dump for CORP-DC01, make sure this gets entered\n",
                encoding="utf-8",
            )

            m.ollama_chat = lambda *a, **kw: "Nothing notable."

            def fake_extract(content, args):
                assert "it missed the cleartext password" in content
                return {
                    "tool": "ldapsearch",
                    "credentials": [{"username": "svc_ldap", "password": "Summer2026!",
                                      "hash": "", "hash_type": "", "host": "CORP-DC01",
                                      "confidence": "high", "notes": "from comment"}],
                    "usernames": [],
                }
            m._llm_extract_tool_output = fake_extract

            class Args:
                ollama_url = "http://localhost:11434"
                model = "test"
                temperature = 0.1
                skip_validation = True
                no_ollama = False
                scans_dir = str(vault / "scans")

            ok = m._reparse_and_analyze_scan(scan_path, "Misc", Args(), vault, {})
            assert ok

            creds_md = (vault / "Loot" / "Credentials.md").read_text(encoding="utf-8")
            assert "svc_ldap" in creds_md
            assert "Summer2026!" in creds_md
            assert "CORP-DC01" in creds_md

            updated_note = scan_path.read_text(encoding="utf-8")
            assert "Operator-guided re-extraction" in updated_note
    finally:
        m.ollama_chat = orig_ollama_chat
        m._llm_extract_tool_output = orig_llm_extract


# --------------------------------------------------------------------------
# per-host ## Creds table
# --------------------------------------------------------------------------

_NTLM = "8846f7eaee8fb117ad06bdd830b7586c"  # NTLM of "password" -- public, generic


def _creds_table(*rows: str) -> str:
    return "\n".join(["## Creds", m.CREDS_HINT, "", m.CREDS_TABLE_HEADER,
                      m.CREDS_TABLE_SEP, *rows])


def _creds_md_section(vault: Path, header_fragment: str) -> str:
    """Return the text of the Credentials.md section whose header contains
    header_fragment (up to the next '## ')."""
    text = (vault / "Loot" / "Credentials.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.startswith("## ") and header_fragment in l)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
               len(lines))
    return "\n".join(lines[start:end])


def test_host_creds_table_syncs_to_credentials_md():
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        hosts_dir = vault / "Hosts"
        hosts_dir.mkdir()
        (hosts_dir / "corp-ws01.md").write_text(
            "---\nip: 10.10.10.5\nhostnames: [\"corp-ws01\"]\n---\n\n"
            + _creds_table(
                "| svc_sql | Summer2026! | MSSQL only |",
                f"| `Administrator` | {_NTLM} | local admin |",
                "| bob | pa\\|ss |  |",           # escaped pipe inside a cell
                "|  |  |  |",                    # untouched template row
            )
            + "\n\n## Open Ports\n- **445/tcp** - smb\n",
            encoding="utf-8",
        )

        assert m._sync_host_creds_tables(vault) == 3
        sec = _creds_md_section(vault, "corp-ws01")
        assert sec.splitlines()[0] == "## [[Hosts/corp-ws01|corp-ws01]]", \
            "new section must link back to the host note"
        assert "Summer2026!" in sec and "MSSQL only" in sec
        assert "pa|ss" in sec or "pa\\|ss" in sec
        admin_row = next(l for l in sec.splitlines() if "Administrator" in l)
        cells = [c.strip() for c in admin_row.strip("|").split("|")]
        # Username | Password | Hash | Hash Type | Source | Notes
        assert cells[1] in ("", "—") and _NTLM in cells[2] and "NTLM" in cells[3], \
            f"hash landed in the wrong column: {admin_row}"
        assert "Host note" in cells[4]

        # Rows stay in the host table, so every later run re-reads them:
        # that must not duplicate anything.
        assert m._sync_host_creds_tables(vault) == 0
        assert _creds_md_section(vault, "corp-ws01").count("svc_sql") == 1


def test_host_creds_table_reuses_existing_host_section():
    """Loot-generated sections are keyed by display name; Injestor ones by
    IP. The sync must land in whichever already exists for this host rather
    than giving the host a second section."""
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        (vault / "Hosts").mkdir()
        (vault / "Loot").mkdir()
        (vault / "Loot" / "Credentials.md").write_text(
            "# Credentials & Users\n\n"
            "## [[Hosts/dc01.corp.local|10.10.10.10]]\n\n"
            "| Username | Password | Hash | Hash Type | Source | Notes |\n"
            "|----------|----------|------|-----------|--------|-------|\n"
            "| `alice` | `Winter2026!` | — | — | loot.txt | — |\n",
            encoding="utf-8",
        )
        (vault / "Hosts" / "dc01.corp.local.md").write_text(
            "---\nip: 10.10.10.10\nhostnames: [\"dc01.corp.local\"]\n---\n\n"
            + _creds_table("| krbtgt | " + _NTLM + " | from DCSync |") + "\n",
            encoding="utf-8",
        )
        assert m._sync_host_creds_tables(vault) == 1
        text = (vault / "Loot" / "Credentials.md").read_text(encoding="utf-8")
        host_headers = [l for l in text.splitlines()
                        if l.startswith("## ") and ("dc01" in l or "10.10.10.10" in l)]
        assert len(host_headers) == 1, f"host got a duplicate section: {host_headers}"
        sec = _creds_md_section(vault, "10.10.10.10")
        assert "alice" in sec and "krbtgt" in sec


def test_existing_host_note_gets_creds_table_inserted():
    """Vaults that predate the section get it without a re-scan, in
    BODY_SECTION_ORDER position: after Critical Findings, before Open Ports."""
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        (vault / "Hosts").mkdir()
        note = vault / "Hosts" / "10.10.10.5.md"
        note.write_text(
            "---\nip: 10.10.10.5\n---\n\n**IP:** 10.10.10.5\n\n"
            "## Critical Findings\n- smb-vuln-ms17-010\n\n"
            "## Open Ports\n- **445/tcp** - smb\n\n## Operator Notes\nkeep me\n",
            encoding="utf-8",
        )
        assert m._sync_host_creds_tables(vault) == 0
        text = note.read_text(encoding="utf-8")
        assert text.index("## Critical Findings") < text.index("## Creds") \
            < text.index("## Open Ports")
        assert "smb-vuln-ms17-010" in text and "keep me" in text
        assert "ip: 10.10.10.5" in text
        before = text
        m._sync_host_creds_tables(vault)
        assert note.read_text(encoding="utf-8") == before, "inserted twice"


def test_writers_preserve_filled_creds_table():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        text = note.read_text(encoding="utf-8")
        note.write_text(
            text.replace("## Open Ports", _creds_table("| svc_backup | Spring2026! | via SMB share |")
                         + "\n\n## Open Ports", 1),
            encoding="utf-8",
        )
        m._write_host_note(hosts_dir, fixtures.NMAP_HOST, "New - Nmap", "New", "Nmap")
        after = note.read_text(encoding="utf-8")
        assert "| svc_backup | Spring2026! | via SMB share |" in after
        assert after.count("## Creds") == 1


def test_merge_unions_creds_tables():
    keep = _creds_table("| alice | Winter2026! | |", "|  |  |  |")
    other = _creds_table("| ALICE | Winter2026! | dup |", "| bob | Hunter2! | |")
    merged = m._merge_creds_sections(keep.split("\n", 1)[1], other.split("\n", 1)[1])
    rows = m._parse_host_creds_table(merged)
    assert [r["username"] for r in rows] == ["alice", "bob"], rows
    assert merged.count(m.CREDS_TABLE_HEADER) == 1, "second header row mid-table"


def test_injestor_new_ip_with_hostname_does_not_crash():
    """Creating a host note for a new IP looked for nearby hostnames in an
    undefined variable, so any paste with both raised NameError after the
    note was created but before the archive was written and the page reset."""
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        (vault / "Hosts").mkdir()
        (vault / "Injestor.md").write_text(
            m._INJESTOR_TEMPLATE.replace(
                "## Notes\n\n", "## Notes\n\n10.10.10.20 fs01.corp.local\n\n"),
            encoding="utf-8",
        )
        result = m._process_injestor(vault)
        assert result is not None and "10.10.10.20" in result["new_hosts"]
        note = (vault / "Hosts" / "10.10.10.20.md").read_text(encoding="utf-8")
        assert "fs01.corp.local" in note, "hostname next to the IP not associated"
        assert "## Creds" in note
        assert (vault / "Injestor.md").read_text(encoding="utf-8") == m._INJESTOR_TEMPLATE


# --------------------------------------------------------------------------
# pivots
# --------------------------------------------------------------------------

def _pivot_vault(tmp: Path) -> Path:
    """web01 (10.10.10.5) is the foothold; dc02/db01 sit in 172.16.2.0/24."""
    hosts = tmp / "Hosts"
    hosts.mkdir()
    for stem, ip, hn in [("web01", "10.10.10.5", "web01.corp.local"),
                         ("dc02", "172.16.2.10", "dc02.corp.local"),
                         ("db01", "172.16.2.20", "db01.corp.local")]:
        (hosts / f"{stem}.md").write_text(
            f"---\nip: {ip}\nhostnames: [\"{hn}\"]\n---\n\n**IP:** {ip}\n\n"
            "## Open Ports\n- **445/tcp** - smb\n\n## Access\n| x |\n\n"
            "## Scan References\n\n## Operator Notes\nmine\n",
            encoding="utf-8",
        )
    return tmp


def test_parse_pivot_line_directions_and_methods():
    with tempfile.TemporaryDirectory() as td:
        idx = m._build_pivot_host_index(_pivot_vault(Path(td)))

        def edges(line):
            pv, err = m._parse_pivot_line(line, idx)
            assert err is None, f"{line!r}: {err}"
            return [(p["from"][1], p["to"][1], p["method"]) for p in pv]

        assert edges("ligolo agent on web01 gives access to 172.16.2.0/24") == \
            [("web01", "172.16.2.0/24", "ligolo")]
        assert edges("- pivot from 10.10.10.5 to dc02 with chisel") == \
            [("web01", "dc02", "chisel")]
        assert edges("web01 -> dc02 -> 10.10.20.0/24") == \
            [("web01", "dc02", ""), ("dc02", "10.10.20.0/24", "")]
        assert edges("reach 172.16.2.x through web01.corp.local using sshuttle") == \
            [("web01", "172.16.2.0/24", "sshuttle")]
        assert edges("ssh -D 1080 on web01 to reach db01 and dc02") == \
            [("web01", "db01", "ssh tunnel"), ("web01", "dc02", "ssh tunnel")]
        # an IP with no host note yet is kept as an IP
        assert edges("web01 gives access to 10.10.30.7") == [("web01", "10.10.30.7", "")]

        for bad in ("ligolo on machineA gives access to machineB",
                    "from 172.16.2.0/24 to web01"):
            pv, err = m._parse_pivot_line(bad, idx)
            assert not pv and err, f"should be rejected, not guessed: {bad!r}"


def test_injestor_pivots_reach_pivots_md_host_notes_and_archive():
    with tempfile.TemporaryDirectory() as td:
        vault = _pivot_vault(Path(td))
        (vault / "Injestor.md").write_text(
            m._INJESTOR_TEMPLATE.replace(
                "## Pivots\n\n",
                "## Pivots\n\n"
                "ligolo agent on web01 gives access to 172.16.2.0/24\n"
                "pivot from dc02 to 10.10.30.7 with chisel\n"
                "tunnel through the thing\n\n"),
            encoding="utf-8",
        )
        result = m._process_injestor(vault)
        assert result["pivots_added"] == 2, result
        assert len(result["pivots_unparsed"]) == 1

        # new IP named in a pivot got its own host note, and the row links it
        assert "10.10.30.7" in result["new_hosts"]
        page = (vault / "Pivots.md").read_text(encoding="utf-8")
        assert "[[Hosts/web01\\|web01]] | 172.16.2.0/24 | ligolo" in page
        assert "[[Hosts/dc02\\|dc02]] | [[Hosts/10.10.30.7\\|10.10.30.7]] | chisel" in page

        web01 = (vault / "Hosts" / "web01.md").read_text(encoding="utf-8")
        assert "**Pivot point -- gives access to:**" in web01
        assert "`172.16.2.0/24` via ligolo -- known hosts:" in web01
        assert "[[Hosts/dc02|dc02]]" in web01 and "[[Hosts/db01|db01]]" in web01
        # placed by BODY_SECTION_ORDER: after Access, before Scan References
        assert web01.index("## Access") < web01.index("## Pivots") < web01.index("## Scan References")
        assert web01.rstrip().endswith("mine"), "operator notes disturbed"

        db01 = (vault / "Hosts" / "db01.md").read_text(encoding="utf-8")
        assert "**Reached through:**" in db01
        assert "[[Hosts/web01|web01]] via ligolo (subnet `172.16.2.0/24`)" in db01
        dc02 = (vault / "Hosts" / "dc02.md").read_text(encoding="utf-8")
        assert "**Reached through:**" in dc02 and "**Pivot point" in dc02

        archive = (vault / "Scans" / f"{result['scan_stem']}.md").read_text(encoding="utf-8")
        assert "tunnel through the thing" in archive and "Not understood" in archive
        assert (vault / "Injestor.md").read_text(encoding="utf-8") == m._INJESTOR_TEMPLATE

        # re-entering the same pivot is not duplicated
        (vault / "Injestor.md").write_text(m._INJESTOR_TEMPLATE.replace(
            "## Pivots\n\n", "## Pivots\n\nweb01 -> 172.16.2.0/24\n\n"), encoding="utf-8")
        assert m._process_injestor(vault)["pivots_added"] == 0
        assert (vault / "Pivots.md").read_text(encoding="utf-8").count("| [[Hosts/web01\|web01]] | 172.16.2.0/24 |") == 1


def test_pivot_sections_follow_pivots_md_edits():
    """Pivots.md is the source of truth: deleting a row there removes the
    generated host-note sections; refreshing twice changes nothing."""
    with tempfile.TemporaryDirectory() as td:
        vault = _pivot_vault(Path(td))
        idx = m._build_pivot_host_index(vault)
        m._add_pivots(vault, m._parse_pivot_line("web01 -> dc02", idx)[0], "test", idx)
        assert m._refresh_pivots(vault) == 2
        assert m._refresh_pivots(vault) == 0, "refresh is not idempotent"
        dc02 = vault / "Hosts" / "dc02.md"
        assert "## Pivots" in dc02.read_text(encoding="utf-8")

        page = vault / "Pivots.md"
        page.write_text("\n".join(l for l in page.read_text(encoding="utf-8").splitlines()
                                  if "dc02" not in l) + "\n", encoding="utf-8")
        m._refresh_pivots(vault)
        text = dc02.read_text(encoding="utf-8")
        assert "## Pivots" not in text
        assert "## Access" in text and text.rstrip().endswith("mine")


def test_writers_preserve_pivot_section():
    with tempfile.TemporaryDirectory() as td:
        hosts_dir, note = _seeded_host(Path(td))
        text = note.read_text(encoding="utf-8")
        note.write_text(text.replace("## Operator Notes",
                                     "## Pivots\n**Reached through:**\n- x\n\n## Operator Notes", 1),
                        encoding="utf-8")
        m._write_host_note(hosts_dir, fixtures.NMAP_HOST, "New - Nmap", "New", "Nmap")
        assert "**Reached through:**" in note.read_text(encoding="utf-8")


def test_canvas_pivot_overlay_edges_and_idempotence():
    with tempfile.TemporaryDirectory() as td:
        vault = _pivot_vault(Path(td))
        idx = m._build_pivot_host_index(vault)
        rows = []
        for line in ("ligolo on web01 gives access to 172.16.2.0/24",
                     "dc02 -> 10.10.20.0/24"):
            rows += m._parse_pivot_line(line, idx)[0]
        data = {"nodes": [
            {"id": "w", "type": "file", "file": "Hosts/web01.md", "x": 0, "y": 0, "width": 360, "height": 220},
            {"id": "d", "type": "file", "file": "Hosts/dc02.md", "x": 500, "y": 0, "width": 360, "height": 220},
            {"id": "g", "type": "group", "label": "172.16.2.0/24", "x": 400, "y": -60, "width": 900, "height": 400},
            {"id": "manual", "type": "text", "text": "operator node", "x": 0, "y": 900, "width": 100, "height": 100},
        ], "edges": [{"id": "scan-edge", "fromNode": "w", "toNode": "d"}]}

        m._add_pivots_to_canvas(data, rows, idx)
        pivot_edges = {(e["fromNode"], e["toNode"]): e for e in data["edges"]
                       if e["id"].startswith(m.PIVOT_ID_PREFIX)}
        assert ("w", "g") in pivot_edges, "subnet target must point at its group"
        assert pivot_edges[("w", "g")]["label"] == "pivot · ligolo"
        assert pivot_edges[("w", "g")]["color"] == m.PIVOT_CANVAS_COLOR
        unscanned = [n for n in data["nodes"] if "10.10.20.0/24" in n.get("text", "")
                     and n["id"].startswith(m.PIVOT_ID_PREFIX) and "Pivot Paths" not in n["text"]]
        assert len(unscanned) == 1 and ("d", unscanned[0]["id"]) in pivot_edges
        panel = next(n for n in data["nodes"] if "## Pivot Paths" in n.get("text", ""))
        # dc02 sits inside web01's subnet, so the chain continues through it
        assert "**web01** --ligolo--> 172.16.2.0/24 (dc02) --pivot--> 10.10.20.0/24" in panel["text"]

        snapshot = json.dumps(data, sort_keys=True)
        m._add_pivots_to_canvas(data, rows, idx)
        assert json.dumps(data, sort_keys=True) == snapshot, "re-applying changed the canvas"

        m._add_pivots_to_canvas(data, [], idx)
        assert not any(x["id"].startswith(m.PIVOT_ID_PREFIX) for x in data["nodes"] + data["edges"])
        assert any(n["id"] == "manual" for n in data["nodes"]), "operator node dropped"
        assert any(e["id"] == "scan-edge" for e in data["edges"])


def test_install_injestor_adds_pivots_section_to_existing_page():
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        old = m._INJESTOR_TEMPLATE.replace(m._INJESTOR_PIVOTS_BLOCK, "")
        old = old.replace("## Notes\n\n", "## Notes\n\nhalf-typed note\n\n")
        (vault / "Injestor.md").write_text(old, encoding="utf-8")
        m._install_injestor(vault)
        text = (vault / "Injestor.md").read_text(encoding="utf-8")
        assert "## Pivots" in text and "half-typed note" in text
        m._install_injestor(vault)
        assert (vault / "Injestor.md").read_text(encoding="utf-8").count("\n## Pivots\n") == 1
        assert (vault / "Pivots.md").exists()


def test_next_steps_explains_how_to_run_analysis_then_reads_saved_analysis():
    with tempfile.TemporaryDirectory() as td:
        vault = Path(td)
        (vault / "Scans").mkdir()
        (vault / "Scans" / "a - Nmap.md").write_text(
            "# a - Nmap\n\n## Analysis\n\n_No AI analysis generated._\n", encoding="utf-8")
        howto = m._build_next_steps([], vault)
        for must in ("/analyze-full", "/refresh", "--reanalyze", "ollama serve"):
            assert must in howto, must

        # interactive /analyze writes into the scan note, not all_analyses
        (vault / "Scans" / "a - Nmap.md").write_text(
            "# a - Nmap\n\n## Analysis\n\n## Potential Attack Paths\n"
            "- Kerberoast svc_sql from web01 and crack offline\n\n## Operator Notes\n",
            encoding="utf-8")
        filled = m._build_next_steps([], vault)
        assert "Kerberoast svc_sql from web01" in filled
        assert "/analyze-full" not in filled


# --------------------------------------------------------------------------
# a truncated scan file must not abort the run
# --------------------------------------------------------------------------

_GOOD_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 10.10.10.5" start="1700000000" version="7.95">
<host><status state="up"/>
<address addr="10.10.10.5" addrtype="ipv4"/>
<hostnames><hostname name="corp-ws01" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="445"><state state="open"/>
<service name="microsoft-ds" product="Windows SMB"/></port>
</ports>
</host>
</nmaprun>
"""

# What an interrupted `nmap -oA` leaves behind: no </nmaprun>, ends mid-run.
_TRUNCATED_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS 10.10.10.6" start="1700000000" version="7.95">
<hosthint><status state="up"/>
<address addr="10.10.10.6" addrtype="ipv4"/>
</hosthint>
<taskprogress task="SYN Stealth Scan" percent="42.35"/>
"""

_TRUNCATED_NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2><Report name="partial"><ReportHost name="10.10.10.7">
"""


def test_truncated_scan_file_does_not_abort_run_or_skip_canvas():
    """An interrupted Nmap scan (or partial Nessus export) in scans/ used to
    raise ParseError out of _run_processing, so no later scan was processed
    and the canvases, Campaign Targets and incremental state were never
    written. The bad file must be skipped; everything else must still land."""
    import os
    orig_cwd, orig_argv = os.getcwd(), sys.argv
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        nmap_dir = tmp / "scans" / "nmap"
        nessus_dir = tmp / "scans" / "nessus"
        nmap_dir.mkdir(parents=True)
        nessus_dir.mkdir(parents=True)
        # "a_" sorts before "b_": the bad file is hit first, as in the
        # reported case, so a crash would also lose the good scan.
        (nmap_dir / "a_truncated.xml").write_text(_TRUNCATED_NMAP_XML, encoding="utf-8")
        (nmap_dir / "b_good.xml").write_text(_GOOD_NMAP_XML, encoding="utf-8")
        (nessus_dir / "partial.nessus").write_text(_TRUNCATED_NESSUS, encoding="utf-8")
        try:
            os.chdir(tmp)  # keep the real maipper.conf / RAG index out of it
            sys.argv = ["mAIpper.py", "--no-ollama", "--no-auto-build",
                        "--scans-dir", "scans", "--vault", "Vault"]
            m.main()
        finally:
            os.chdir(orig_cwd)
            sys.argv = orig_argv

        vault = tmp / "Vault"
        assert (vault / "Assessment Canvas.canvas").exists(), \
            "canvas not written -- run aborted on the truncated file"
        assert (vault / "Hosts" / "_Campaign Targets.md").exists()
        assert any("10.10.10.5" in p.read_text(encoding="utf-8")
                   for p in (vault / "Hosts").glob("*.md")), \
            "good scan after the truncated one was not processed"
        state = (vault / m.STATE_FILENAME).read_text(encoding="utf-8")
        assert "b_good.xml" in state
        assert "a_truncated.xml" not in state, \
            "truncated file marked analyzed -- it would never be retried"


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
