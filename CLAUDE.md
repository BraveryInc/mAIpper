# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**mAIpper** is a single-file Python CLI tool (`mAIpper-v0.6.py`) for pentesters. It ingests Nmap XML scan output, queries a local LLM via **Ollama**, and writes structured **Obsidian notes** (Markdown + Canvas JSON) for use in an Obsidian vault.

## Running the Tool

```bash
# Basic usage — processes all XML files under ./scans/nmap/
python mAIpper-v0.6.py

# Single file
python mAIpper-v0.6.py --xml scans/nmap/internal.xml

# Skip AI, skip canvas, custom vault output dir
python mAIpper-v0.6.py --no-ollama --no-canvas --vault MyNotes

# Remote Ollama instance, different model
python mAIpper-v0.6.py --ollama-url http://10.10.10.5:11434 --model llama3:8b

# Canvas layout tuning
python mAIpper-v0.6.py --canvas-cols 3 --canvas-groups-per-row 4

# Verbose / debug logging
python mAIpper-v0.6.py -v      # INFO
python mAIpper-v0.6.py -vv     # DEBUG
```

There are no tests, no build steps, and no package install — only `requests` is required beyond the stdlib:

```bash
pip install requests
```

Ollama must be running locally (`ollama start`) before invoking unless `--no-ollama` is used. Recommended model: `qwen2.5:14b-instruct-q5_K_M`.

## Architecture

Everything lives in `mAIpper-v0.6.py`. The flow is linear:

1. **`main`** — resolves scan files, collects `scan_host_map` and `all_analyses` across all files, then calls vault + canvas writers
2. **`parse_nmap_xml`** — parses XML into a dict: `hosts[]` each with `addresses`, `hostnames`, `open_ports[]`, and per-port `scripts[]`
3. **`build_ollama_prompt` / `ollama_chat`** — assembles a structured prompt (with per-port hints from `get_port_hints`) and POSTs to `/api/generate` (non-streaming)
4. **`create_obsidian_vault`** → **`_write_host_note`** — writes `Hosts/<host>.md` and `Scans/<scan>.md`; on re-run, host notes are **merged** (new ports/sources added, `status` and `## Operator Notes` preserved)
5. **`build_canvas`** — full canvas rebuild: Campaign Overview text node → scan file cards → subnet group nodes (hosts inside, color-coded by status) → Next Steps text node; edges connect overview→scans and scans→hosts

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
├─ Hosts/<hostname-or-ip>.md    # frontmatter + open ports + ## Operator Notes
├─ Scans/<scan-name> - Nmap.md  # per-scan note with AI analysis section
└─ Assessment Canvas.canvas     # single pane of glass
```

## Key Conventions

- `safe_filename()` strips characters illegal in Obsidian/Windows filenames before writing any path.
- Obsidian internal links use `[[Hosts/<stem>|display]]` syntax — no `.md` extension in the link target.
- Canvas file node paths are relative to the vault root, forward slashes only.
- Ollama is called with `stream: false`; the full response is expected in `response.json()["response"]`.
- The tool is version-numbered in the filename. When creating the next version, copy the file and increment the version number rather than editing in place.
