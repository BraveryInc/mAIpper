#!/usr/bin/env python3
"""Shared test fixtures for the mAIpper test suite.

Kept in one module so the behavioural tests (test_note_writing.py) and the
golden-output tests (test_writer_output.py) exercise the writers with
identical inputs. All values are synthetic -- see the "Example data must be
generic" rule in CLAUDE.md.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

BS = chr(92)  # backslash, kept out of literals so this file stays escape-free

MODULE_PATH = Path(__file__).resolve().parent.parent / "mAIpper.py"


def load_maipper(name: str = "maipper_under_test"):
    """Import mAIpper.py as a module without requiring it to be on sys.path."""
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# A host note that already carries content from every other source, plus
# operator-authored sections. Writers must merge into this without loss.
# ---------------------------------------------------------------------------

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

# Frontmatter keys that must survive a write by a writer that does not own them
PRESERVED = {
    "ips": ["172.16.1.100", "192.168.50.5"],
    "domain": "CORP",
    "nessus_max_severity": 4,
    "autorecon_tools_run": 15,
    "loot_file_count": 3,
    "loot_credential_count": 7,
    "loot_hash_count": 2,
}

# Body content that must survive every writer
OPERATOR_CONTENT = ("## Access", "psexec", "## NXC Enumeration", "operator wrote this")


# ---------------------------------------------------------------------------
# Per-source inputs
# ---------------------------------------------------------------------------

NMAP_HOST = {
    "state": "up",
    "addresses": [{"addr": "10.10.10.5", "addrtype": "ipv4"}],
    "hostnames": [{"name": "dc01.corp.local", "type": "PTR"}],
    "open_ports": [
        {
            "protocol": "tcp",
            "port": 445,
            "service": {"name": "microsoft-ds", "product": "Windows Server 2019",
                        "version": "10.0", "extrainfo": "", "tunnel": ""},
            "scripts": [],
        },
        {
            "protocol": "tcp",
            "port": 389,
            "service": {"name": "ldap", "product": "Active Directory LDAP",
                        "version": "", "extrainfo": "", "tunnel": ""},
            "scripts": [],
        },
    ],
}

NESSUS_FINDINGS = [
    {
        "plugin_id": "12345", "plugin_name": "SMB Signing Disabled",
        "severity_int": 3, "port": 445, "protocol": "tcp",
        "description": "Signing is not required.", "solution": "Enforce SMB signing.",
        "cves": ["CVE-2016-2115"], "cvss_base": "5.0", "cvss3_base": "5.3",
        "plugin_output": "",
    },
    {
        "plugin_id": "99999", "plugin_name": "TLS Version Detection",
        "severity_int": 0, "port": 443, "protocol": "tcp",
        "description": "Informational.", "solution": "n/a",
        "cves": [], "cvss_base": "", "cvss3_base": "", "plugin_output": "",
    },
]

BURP_ISSUES = [
    {
        "name": "Cross-site scripting (reflected)", "path": "/search",
        "location": "/search?q=", "severity": "High", "confidence": "Certain",
        "issue_detail": "Reflected input.", "issue_background": "XSS background.",
        "remediation_detail": "Encode output.", "remediation_background": "General.",
    },
]

AUTORECON_TARGET = {
    "target": "10.10.10.5", "ip": "10.10.10.5", "hostname": "dc01.corp.local",
    "tool_results": {
        "tcp/445": [
            {"tool": "enum4linux", "filename": "tcp_445_smb_enum4linux.txt",
             "data": {"tool": "enum4linux", "os_info": "Windows Server 2019",
                      "domain": "CORP", "workgroup": "", "null_session": True,
                      "users": ["administrator", "svc_sql"],
                      "shares": [{"name": "SYSVOL", "access": "read"}],
                      "groups": ["Domain Admins"], "password_policy": {"min_length": 7}}},
        ],
    },
    "commands_log": "enum4linux -a 10.10.10.5", "manual_commands": "",
    "nmap_xml_files": [],
    "summary": {"total_tools_run": 9, "tools_with_findings": 1,
                "technologies": [], "writable_shares": [], "null_session": True,
                "users_found": ["administrator", "svc_sql"], "weak_tls": [],
                "community_strings": []},
}

LOOT_FILES = [
    {
        "filename": "creds.txt", "filepath": "/scans/loot/10.10.10.5/creds.txt",
        "size_bytes": 64,
        "credentials": [
            {"username": "svc_sql", "password": "ExamplePassword1", "cred_type": "cleartext",
             "source_pattern": "colon", "inline_note": ""},
        ],
        "hashes": [
            {"hash": "0" * 32, "hash_type": "NTLM", "username": "administrator",
             "context_line": "administrator:500:...:...:::"},
        ],
        "file_listings": [], "network_refs": [], "standalone_usernames": ["backup_svc"],
        "raw_preview": "svc_sql:ExamplePassword1", "category": "credentials",
    },
]

NXC_HOST = {
    "ip": "10.10.10.5", "hostname": "DC01", "domain": "corp.local",
    "os": "Windows Server 2019 Build 17763", "dc": True,
    "signing": True, "smbv1": False, "zerologon": False, "petitpotam": False,
    "null_session": False,
    "shares": [
        {"name": "SYSVOL", "read": True, "write": False, "remark": "Logon server share"},
        {"name": "Data", "read": True, "write": True, "remark": ""},
    ],
    "protocol": "smb", "source": "db",
}

# LLM output that used to crash re.sub when used as a replacement template
BACKSLASH_PAYLOADS = [
    "Authenticate as DOMAIN" + BS + "Administrator.",
    "Mount " + BS * 2 + "10.10.10.5" + BS + "C$ with smbclient.",
    "Stage the payload in C:" + BS + "Windows" + BS + "Temp.",
    "The pattern (a)" + BS + "1 matched twice.",
    "Check the " + BS + "group directory.",
]


def seed_host_note(tmp: Path) -> tuple[Path, Path]:
    """Create a Hosts/ dir containing the rich HOST_NOTE. Returns (hosts_dir, note)."""
    hosts_dir = tmp / "Hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    note = hosts_dir / "10.10.10.5.md"
    note.write_text(HOST_NOTE, encoding="utf-8")
    return hosts_dir, note


def empty_hosts_dir(tmp: Path) -> Path:
    """Create an empty Hosts/ dir, for exercising note creation from scratch."""
    hosts_dir = tmp / "Hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    return hosts_dir
