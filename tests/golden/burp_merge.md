===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: exploited
tags: ["smb", "ldap"]
sources: ["Prior - Nmap", "Internal - Burp"]
ips: ["172.16.1.100", "192.168.50.5"]
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

## Burp Suite Findings
#### [High (Certain)] Cross-site scripting (reflected)
- [ ] Investigate: Burp Cross-site scripting (reflected) (High)
**Path:** `/search`
**Location:** /search?q=

Reflected input.

**Remediation:** Encode output.

## NXC Enumeration
signing: false

## Access
| User | Priv | Method |
| --- | --- | --- |
| adm | SYSTEM | psexec |

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]
- [[Scans/Internal - Burp|Internal - Burp]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this