===== dc01.corp.local.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: not-started
tags: []
sources: ["Internal - Nessus"]
nessus_max_severity: 3
---

**IP:** 10.10.10.5
**Hostname:** dc01.corp.local

## Nessus Findings
#### [High] SMB Signing Disabled (Plugin 12345)
- [ ] Investigate: Nessus SMB Signing Disabled (Plugin 12345, High)
**Port:** tcp/445  ·  **CVSS v3:** 5.3  ·  **CVE(s):** CVE-2016-2115

Signing is not required.

**Solution:** Enforce SMB signing.

_Plus 1 informational finding(s) — omitted for brevity._

## Scan References
- [[Scans/Internal - Nessus|Internal - Nessus]]

## Operator Notes
_Add your own findings, observations, and next steps below._