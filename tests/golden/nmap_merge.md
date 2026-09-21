===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: exploited
tags: ["ldap", "smb"]
sources: ["Prior - Nmap", "Internal - Nmap"]
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
**Open Ports:** 2

## Open Ports
- **tcp/389** — ldap Active Directory LDAP
  - [ ] Investigate: LDAP (tcp/389)
- **tcp/445** — microsoft-ds Windows Server 2019 10.0
  - [ ] Investigate: MICROSOFT-DS (tcp/445)

## NXC Enumeration
signing: false

## Access
| User | Priv | Method |
| --- | --- | --- |
| adm | SYSTEM | psexec |

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]
- [[Scans/Internal - Nmap|Internal - Nmap]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this