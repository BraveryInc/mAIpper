===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: exploited
tags: ["smb", "ldap"]
sources: ["Prior - Nmap", "Internal - Nessus"]
nessus_max_severity: 4
ips: ["172.16.1.100", "192.168.50.5"]
domain: CORP
autorecon_tools_run: 15
loot_file_count: 3
loot_credential_count: 7
loot_hash_count: 2
critical_flags: ["Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) (CVE-2017-0143) - tcp/445"]
---

**State:** up
**IP:** 10.10.10.5

## Critical Findings
- [CONFIRMED] **Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)** (tcp/445) — `smb-vuln-ms17-010` CVE-2017-0143 — risk: HIGH

## Creds
_One row per credential for this host. Password takes a cleartext password or a hash. Synced to [[Loot/Credentials|Credentials]] on the next run (or Enter in interactive mode)._

| Username | Password | Notes |
|----------|----------|-------|
|  |  |  |

## Open Ports
- **445/tcp** - microsoft-ds
  - [ ] Investigate: SMB (tcp/445)

## Nessus Findings
#### [High] SMB Signing Disabled (Plugin 12345)
- [ ] Investigate: Nessus SMB Signing Disabled (Plugin 12345, High)
**Port:** tcp/445  ·  **CVSS v3:** 5.3  ·  **CVE(s):** CVE-2016-2115

Signing is not required.

**Solution:** Enforce SMB signing.

_Plus 1 informational finding(s) — omitted for brevity._

## NXC Enumeration
signing: false

## Access
| User | Priv | Method |
| --- | --- | --- |
| adm | SYSTEM | psexec |

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]
- [[Scans/Internal - Nessus|Internal - Nessus]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this