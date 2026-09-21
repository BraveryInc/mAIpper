===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local", "DC01"]
status: exploited
tags: ["domain-controller", "ldap", "smb"]
sources: ["Prior - Nmap", "NXC - SMB"]
nessus_max_severity: 4
ips: ["172.16.1.100", "192.168.50.5"]
domain: CORP
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

## NXC Enumeration
| Field | Value |
|-------|-------|
| Protocol | SMB |
| OS | Windows Server 2019 Build 17763 |
| Domain | corp.local |
| Domain Controller | Yes |
| SMB Signing | Enabled |
| SMBv1 | Disabled |
| Null Session | No |

### Shares

| Share | Read | Write | Remark |
|-------|------|-------|--------|
| SYSVOL | ✓ |  | Logon server share |
| Data | ✓ | ✓ |  |

## Scan References
- [[Scans/Prior - Nmap|Prior - Nmap]]
- [[Scans/NXC - SMB|NXC - SMB]]

## Operator Notes
_Add your own findings, observations, and next steps below._

operator wrote this