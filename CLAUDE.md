# CLAUDE.md

This file provides guidance when working with code in this repository.

## What This Is

**mAIpper** is a single-file Python CLI tool (`mAIpper-v0.7.py`) for pentesters. It ingests scan output from multiple tools, queries a local LLM via **Ollama**, and writes structured **Obsidian notes** (Markdown + Canvas JSON) for use in an Obsidian vault.

Supported input formats:
- **Nmap XML** (`scans/nmap/*.xml`)
- **Nessus** (`scans/nessus/*.nessus`)
- **Burp Suite Issues XML** (`scans/burp/*.xml`)

## Running the Tool

```bash
# Basic usage — processes all scan files under ./scans/
python mAIpper-v0.7.py

# Single Nmap file
python mAIpper-v0.7.py --xml scans/nmap/internal.xml

# Skip AI, skip canvas, custom vault output dir
python mAIpper-v0.7.py --no-ollama --no-canvas --vault MyNotes

# Skip specific parsers
python mAIpper-v0.7.py --no-nessus --no-burp

# Remote Ollama instance, different model
python mAIpper-v0.7.py --ollama-url http://10.10.10.5:11434 --model llama3:8b

# Export to Excel (requires openpyxl)
python mAIpper-v0.7.py --excel

# Canvas layout tuning
python mAIpper-v0.7.py --canvas-cols 3 --canvas-groups-per-row 4

# Hallucination mitigation tuning
python mAIpper-v0.7.py --temperature 0.1    # lower = less creative (default: 0.15)
python mAIpper-v0.7.py --skip-validation    # bypass post-processing validator

# Verbose / debug logging
python mAIpper-v0.7.py -v      # INFO
python mAIpper-v0.7.py -vv     # DEBUG
```

Dependencies beyond stdlib:

```bash
pip install requests          # required
pip install openpyxl          # required only for --excel
```

Ollama must be running locally (`ollama start`) before invoking unless `--no-ollama` is used. Recommended model: `qwen2.5:14b-instruct-q5_K_M`.

## Architecture

Everything lives in `mAIpper-v0.7.py`. The flow is linear:

1. **`main`** — resolves scan files across all parsers, collects `scan_host_map` and `all_analyses`, calls vault writers and canvas builder, optionally exports Excel
2. **`parse_nmap_xml`** — parses Nmap XML into hosts with `addresses`, `hostnames`, `open_ports[]`, and per-port `scripts[]`
3. **`parse_nessus_xml`** — parses `.nessus` files into hosts with `findings[]` (pluginID, severity 0–4, CVEs, CVSS, description, solution, plugin_output)
4. **`parse_burp_xml`** — parses Burp Issues XML into hosts with `issues[]` (name, severity, confidence, path, detail)
5. **`build_ollama_prompt` / `build_nessus_ollama_prompt` / `build_burp_ollama_prompt`** — assemble structured prompts and POST to Ollama `/api/generate`; Nessus uses a two-pass approach (fact extraction → analysis)
6. **`validate_ai_output`** — post-processing validator that cross-references CVEs, IPs, ports, and hostnames in the AI output against the actual scan input; flags anything that wasn't in the data
7. **`create_obsidian_vault`** / **`create_nessus_vault`** / **`create_burp_vault`** → **`_write_host_note`** — writes and merges host notes; `status` and `## Operator Notes` are always preserved on re-run
8. **`build_canvas`** — full rebuild: Campaign Overview → Priority Targets → scan cards → subnet groups (color-coded) → Next Steps
9. **`export_excel`** — generates `Export.xlsx` with Summary, Nmap, Nessus, and Burp sheets

## Host Note Format

Host notes carry YAML frontmatter that drives canvas behavior:

```yaml
---
ip: 10.10.10.5
hostnames: ["dc01.domain.local"]
status: not-started        # operator editable: not-started / in-progress / done / exploited / blocked
tags: ["smb", "kerberos", "ldap", "domain-controller"]
sources: ["InternalScan - Nmap", "InternalScan - Nessus"]
nessus_max_severity: 4     # 0-4; drives canvas color when status is not-started
---
```

Status colors: yellow = in-progress, green = done, red = exploited, purple = blocked.
Nessus severity colors (when status = not-started): red = critical (4), orange = high (3), yellow = medium (2).

## Canvas Layout

```
[ Campaign Overview — stats + key AI findings ]
              ↓
  [ Priority Targets — AI-ranked attack order ]
       ↓           ↓           ↓
[ Scan Card ]  [ Scan Card ]  [ Scan Card ]
     ↓  ↓              ↓  ↓
┌── 10.10.10.0/24 ──┐  ┌── 192.168.1.0/24 ──┐
│ host  host        │  │ host  host          │
└───────────────────┘  └─────────────────────┘
[ Next Steps — extracted from AI analysis ]
```

- Stable node IDs (`hashlib.md5(semantic_key)`) — operator-added canvas nodes survive re-runs.
- Priority Targets node: AI-ranked list of hosts by exploitation likelihood, citing CVEs/services as evidence.
- Edges: Overview → Priority Targets → subnet groups; scan cards → host cards.

## Output Layout

```
Obsidian/
├─ Hosts/<hostname-or-ip>.md         # frontmatter + open ports + Nessus findings + Burp findings + Operator Notes
├─ Scans/<scan-name> - Nmap.md       # per-scan note with AI analysis + Validation Warnings
├─ Scans/<scan-name> - Nessus.md     # Nessus scan note with AI analysis
├─ Scans/<scan-name> - Burp.md       # Burp scan note with AI analysis
├─ Assessment Canvas.canvas          # single pane of glass
└─ Export.xlsx                       # optional; --excel flag
```

## Hallucination Mitigation

Three-layer approach:

1. **Prompt-level grounding rules** — every prompt instructs the model to tag claims as `[CONFIRMED]`/`[INFERRED]`/`[ASSUMED]`, prohibits inventing CVEs or service details not in the scan data, and requires "insufficient data" instead of guessing.
2. **Temperature control** — default 0.15 (low creativity). Adjustable via `--temperature`.
3. **Post-processing validator** (`validate_ai_output`) — after every Ollama response, cross-references all CVE IDs, IPs, port numbers, and hostnames in the output against the actual input data. Anything that wasn't in the scan gets a `⚠️ HALLUCINATION WARNING` blockquote injected inline, plus a `## Validation Warnings` section in the scan note.

Nessus also uses a **two-pass analysis**: Pass 1 extracts only confirmed facts (no inference), Pass 2 analyzes those facts. This separates fact extraction from reasoning.

## Key Conventions

- `safe_filename()` strips characters illegal in Obsidian/Windows filenames.
- Obsidian internal links use `[[Hosts/<stem>|display]]` syntax — no `.md` extension.
- Canvas file node paths are relative to the vault root, forward slashes only.
- Ollama called with `stream: false`; response in `response.json()["response"]`.
- **Versioning**: copy the file and increment the version number for each new version. Do not edit in place.
- When creating v0.8+, read the v0.7 file fully before starting. Preserve all existing functionality.

## Prompt Architecture

Four prompts, each with the same GROUNDING RULES header:

| Prompt | Function | Key sections |
|--------|----------|--------------|
| Nmap | `build_ollama_prompt` | Environment Assessment, Key Observations, Enumeration Suggestions, Potential Attack Paths, Notable Risks |
| Nessus | `build_nessus_ollama_prompt` | Key Observations, Exploitation Priority ([MSF]/[POC]/[THEORETICAL] tags), Attack Chains, Remediation Focus |
| Burp | `build_burp_ollama_prompt` | Key Observations, Exploitation Priority, Attack Chains, False Positive Risk Assessment, Remediation Focus |
| Priority Targets | `build_priority_targets_prompt` | Numbered ranked list only, evidence citation required per entry |

All prompts require `[CONFIRMED]`/`[INFERRED]`/`[ASSUMED]` tagging and ready-to-run commands with actual target IPs.
