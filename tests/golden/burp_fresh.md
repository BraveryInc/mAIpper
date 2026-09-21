===== dc01.corp.local.md =====
---
ip: 10.10.10.5
hostnames: ["dc01.corp.local"]
status: not-started
tags: []
sources: ["Internal - Burp"]
---

**IP:** 10.10.10.5
**URL:** http://dc01.corp.local/

## Burp Suite Findings
#### [High (Certain)] Cross-site scripting (reflected)
- [ ] Investigate: Burp Cross-site scripting (reflected) (High)
**Path:** `/search`
**Location:** /search?q=

Reflected input.

**Remediation:** Encode output.

## Scan References
- [[Scans/Internal - Burp|Internal - Burp]]

## Operator Notes
_Add your own findings, observations, and next steps below._