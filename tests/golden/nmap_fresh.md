===== dc01.corp.local.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: not-started
tags: ["ldap", "smb"]
sources: ["Internal - Nmap"]
---

**State:** up
**IP:** 10.10.10.5
**Open Ports:** 2

## Creds
_One row per credential for this host. Password takes a cleartext password or a hash. Synced to [[Loot/Credentials|Credentials]] on the next run (or Enter in interactive mode)._

| Username | Password | Notes |
|----------|----------|-------|
|  |  |  |

## Open Ports
- **tcp/445** — microsoft-ds Windows Server 2019 10.0
  - [ ] Investigate: MICROSOFT-DS (tcp/445)
- **tcp/389** — ldap Active Directory LDAP
  - [ ] Investigate: LDAP (tcp/389)

## Scan References
- [[Scans/Internal - Nmap|Internal - Nmap]]

## Operator Notes
_Add your own findings, observations, and next steps below._