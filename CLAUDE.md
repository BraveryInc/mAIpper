# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**mAIpper** is a single-file Python CLI tool (`mAIpper-v0.7.py`) for pentesters. It ingests scan output from **Nmap**, **Nessus**, and **Burp Suite**, queries a local LLM via **Ollama**, and writes structured **Obsidian notes** (Markdown + Canvas JSON) for use in an Obsidian vault. It can also export findings to Excel.

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

# Export findings to Excel
python mAIpper-v0.7.py --excel

# Remote Ollama instance, different model
python mAIpper-v0.7.py --ollama-url http://10.10.10.5:11434 --model llama3:8b

# Canvas layout tuning
python mAIpper-v0.7.py --canvas-cols 3 --canvas-groups-per-row 4

# Verbose / debug logging
python mAIpper-v0.7.py -v      # INFO
python mAIpper-v0.7.py -vv     # DEBUG
```

There are no tests, no build steps, and no package install — only `requests` is required beyond the stdlib:

```bash
pip install requests
```

Ollama must be running locally (`ollama start`) before invoking unless `--no-ollama` is used. Recommended model: `qwen2.5:14b-instruct-q5_K_M`.

## Architecture

Everything lives in `mAIpper-v0.7.py`. The flow is linear:

1. **`main`** — resolves scan files across all three parsers, collects `scan_host_map` and `all_analyses`, then calls vault + canvas writers and optional Excel export
2. **`parse_nmap_xml`** — parses Nmap XML into a dict: `hosts[]` each with `addresses`, `hostnames`, `open_ports[]`, and per-port `scripts[]`
3. **`parse_nessus_xml`** — parses `.nessus` XML from `scans/nessus/`; extracts CVEs, CVSS scores, and plugin findings per host; stores `nessus_max_severity` in frontmatter
4. **`parse_burp_xml`** — parses Burp Suite Pro Scanner XML from `scans/burp/`; extracts web findings (issue name, severity, path, detail) per host
5. **`build_ollama_prompt` / `ollama_chat`** — assembles a structured prompt with grounding rules, AD detection, per-port hints, Nessus CVEs, and Burp findings; POSTs to `/api/generate` (non-streaming)
6. **`create_obsidian_vault`** → **`_write_host_note`** — writes `Hosts/<host>.md` and `Scans/<scan>.md`; on re-run, host notes are **merged** (new ports/sources added, `status` and `## Operator Notes` preserved)
7. **`build_canvas`** — full canvas rebuild: Campaign Overview → scan cards → subnet group nodes (hosts color-coded by status) → Priority Targets node → Next Steps node; edges connect overview→scans→hosts
8. **`export_excel`** — writes `Export.xlsx` with one sheet per scan source (Nmap, Nessus, Burp), requires `openpyxl`

## Host Note Format

Host notes carry YAML frontmatter that drives canvas behavior:

```yaml
---
ip: 10.10.10.5
hostnames: ["dc01.domain.local"]
status: not-started        # operator editable: not-started / in-progress / done / exploited / blocked
tags: ["smb", "kerberos", "ldap", "domain-controller"]
sources: ["InternalScan - Nmap"]
---
```

Changing `status` in Obsidian and re-running mAIpper updates the card's color on the canvas (yellow = in-progress, green = done, red = exploited, purple = blocked).

## Canvas Layout

```
[ Campaign Overview — stats + key AI findings ]
          ↓               ↓
[ Scan Note Card ]  [ Scan Note Card ]
      ↓  ↓  ↓               ↓  ↓
┌── 10.10.10.0/24 ──┐  ┌── 192.168.1.0/24 ──┐
│ host  host        │  │ host  host          │
│ host  host        │  └─────────────────────┘
└───────────────────┘
[ Next Steps — extracted from AI analysis ]
```

- Subnet groups are computed from the `/24` of each host's IPv4.
- Edges connect: Campaign Overview → scan cards → host cards.
- Node IDs are stable (`hashlib.md5(semantic_key)`) — operator-added canvas nodes survive re-runs.

## Output Layout

```
Obsidian/
├─ Hosts/<hostname-or-ip>.md       # frontmatter + open ports/findings + ## Operator Notes
├─ Scans/<scan-name> - Nmap.md     # per-scan note with AI analysis section
├─ Scans/<scan-name> - Nessus.md   # Nessus findings note
├─ Scans/<scan-name> - Burp.md     # Burp Suite findings note
└─ Assessment Canvas.canvas        # single pane of glass
Export.xlsx                        # optional Excel export (--excel flag)
```

## Key Conventions

- `safe_filename()` strips characters illegal in Obsidian/Windows filenames before writing any path.
- Obsidian internal links use `[[Hosts/<stem>|display]]` syntax — no `.md` extension in the link target.
- Canvas file node paths are relative to the vault root, forward slashes only.
- Ollama is called with `stream: false`; the full response is expected in `response.json()["response"]`.
- All prompts include **GROUNDING RULES** to prevent hallucinated ports, services, or CVEs not present in the scan data.
- AD environment detection fires when Kerberos (88), LDAP (389/636), or SMB (445) are present, adding domain-specific analysis sections.
- The tool is version-numbered in the filename. When creating the next version, copy the file and increment the version number rather than editing in place.
