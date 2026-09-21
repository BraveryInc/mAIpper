===== dc01.corp.local.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: not-started
tags: ["autorecon"]
sources: ["10.10.10.5 - AutoRecon"]
nessus_max_severity: 0
autorecon_tools_run: 9
---

**IP:** 10.10.10.5
**Hostname:** dc01.corp.local

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

## Scan References
- [[Scans/10.10.10.5 - AutoRecon|10.10.10.5 - AutoRecon]]

## Operator Notes
_Add your own findings, observations, and next steps below._