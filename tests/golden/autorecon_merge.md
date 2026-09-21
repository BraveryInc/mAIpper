===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: exploited
tags: ["smb", "ldap", "autorecon"]
sources: ["Prior - Nmap", "10.10.10.5 - AutoRecon"]
nessus_max_severity: 4
autorecon_tools_run: 9
ips: ["172.16.1.100", "192.168.50.5"]
domain: CORP
loot_file_count: 3
loot_credential_count: 7
loot_hash_count: 2
---

**State:** up
**IP:** 10.10.10.5

## Open Ports
- **445/tcp** - microsoft-ds
  - [ ] Investigate: SMB (tcp/445)

## AutoRecon Enumeration
**AutoRecon target:** 10.10.10.5 | **Tools run:** 9 | **With findings:** 1

### tcp/445 — smb

**OS:** Windows Server 2019
**Domain:** CORP
**Null Session:** Yes

#### Shares
| Share | Access |
|-------|--------|
| SYSVOL | read |

#### Users Found
`administrator`, `svc_sql`

**Password Policy:** Min length: 7

## NXC Enumeration
signing: false

## Access
| User | Priv | Method |
| --- | --- | --- |
| adm | SYSTEM | psexec |

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]
- [[Scans/10.10.10.5 - AutoRecon|10.10.10.5 - AutoRecon]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this