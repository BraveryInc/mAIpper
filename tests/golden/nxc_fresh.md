===== 10.10.10.5.md =====
---
ip: 10.10.10.5
hostnames: ["DC01"]
status: not-started
tags: ["domain-controller", "smb"]
sources: ["NXC - SMB"]
nessus_max_severity: 0
domain: corp.local
---

**IP:** 10.10.10.5
**Hostname:** DC01

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
- [[Scans/NXC - SMB|NXC - SMB]]

## Operator Notes
_Add your own findings, observations, and next steps below._