===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: exploited
tags: ["smb", "ldap", "loot"]
sources: ["Prior - Nmap", "Loot"]
nessus_max_severity: 4
loot_file_count: 1
loot_credential_count: 1
loot_hash_count: 1
ips: ["172.16.1.100", "192.168.50.5"]
domain: CORP
autorecon_tools_run: 15
---

**State:** up
**IP:** 10.10.10.5

## Open Ports
- **445/tcp** - microsoft-ds
  - [ ] Investigate: SMB (tcp/445)

## NXC Enumeration
signing: false

## Loot
**Loot files:** 1  ·  **Credentials:** 1  ·  **Hashes:** 1

See [[Loot/Credentials|Credentials]] and [[Loot/Hashes|Hashes]] for full details.

## Access
| User | Priv | Method |
| --- | --- | --- |
| adm | SYSTEM | psexec |

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]
- [[Scans/Loot|Loot]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this