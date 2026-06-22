# CLAUDE.md

This file provides guidance when working with code in this repository.

## What This Is

**mAIpper** is a single-file Python CLI tool (`mAIpper-v0.10.py`) for pentesters. It ingests scan output from multiple tools, queries a local LLM via **Ollama**, and writes structured **Obsidian notes** (Markdown + Canvas JSON) for use in an Obsidian vault.

Supported input formats:
- **Nmap XML** (`scans/nmap/*.xml`)
- **Nessus** (`scans/nessus/*.nessus`)
- **Burp Suite Issues XML** (`scans/burp/*.xml`)
- **Nikto** (`scans/nikto/`) — nikto scan output (processed via misc pipeline for now)
- **AutoRecon** (`scans/autorecon/<target>/scans/` or `--autorecon <dir>`)
- **Loot** (`scans/loot/` or `--loot <dir>`) — credentials, hashes, keys, sensitive files
- **Misc** (`scans/misc/` or `--misc <dir>`) — arbitrary tool text output for LLM interpretation

## Running the Tool

```bash
# Basic usage — processes all scan files under ./scans/
python mAIpper-v0.10.py

# Initialize scan directory structure + config file
python mAIpper-v0.10.py --init

# Interactive mode — watch for changes, chat with LLM, drop data
python mAIpper-v0.10.py -i
python mAIpper-v0.10.py -i --watch-interval 60

# Single Nmap file
python mAIpper-v0.10.py --xml scans/nmap/internal.xml

# Skip AI, skip canvas, custom vault output dir
python mAIpper-v0.10.py --no-ollama --no-canvas --vault MyNotes

# Skip specific parsers
python mAIpper-v0.10.py --no-nessus --no-burp --no-autorecon --no-loot --no-misc

# Remote Ollama instance, different model
python mAIpper-v0.10.py --ollama-url http://10.10.10.5:11434 --model llama3:8b

# Export to Excel (requires openpyxl)
python mAIpper-v0.10.py --excel

# Force re-analysis of all files (ignore incremental state)
python mAIpper-v0.10.py --reanalyze

# Hallucination mitigation tuning
python mAIpper-v0.10.py --temperature 0.1    # lower = less creative (default: 0.15)
python mAIpper-v0.10.py --skip-validation    # bypass post-processing validator

# Verbose / debug logging
python mAIpper-v0.10.py -v      # INFO
python mAIpper-v0.10.py -vv     # DEBUG
```

Dependencies beyond stdlib:

```bash
pip install requests          # required
pip install openpyxl          # required only for --excel
```

Ollama must be running locally (`ollama start`) before invoking unless `--no-ollama` is used. Recommended model: `qwen2.5:14b-instruct-q5_K_M`.

## Configuration

`maipper.conf` (INI format) in the working directory. Created by `--init`. CLI flags override config values.

Sections: `[general]` (scans_dir, vault, tool_name, verbose), `[ollama]` (ollama_url, model, temperature), `[canvas]` (canvas_name, canvas_cols, canvas_groups_per_row), `[interactive]` (interactive, watch_interval), `[parsers]` (no_ollama, no_canvas, no_nessus, etc.).

Set `interactive = true` in `[interactive]` to start in interactive mode by default.

## Architecture

Everything lives in `mAIpper-v0.10.py`. The flow is linear:

1. **`main`** — loads config, parses args, handles `--init` and `-i` interactive mode, dispatches to `_run_processing`
2. **`_run_processing`** — loads operator notes, resolves scan files across all parsers, skips unchanged files (incremental state), collects `scan_host_map` and `all_analyses`, processes deep dives, calls vault writers and canvas builder, optionally exports Excel
3. **`parse_nmap_xml`** — parses Nmap XML; filters hosts with no open ports
4. **`parse_nessus_xml`** — parses `.nessus` files; filters hosts with only informational findings
5. **`parse_burp_xml`** — parses Burp Issues XML into hosts with issues
6. **`parse_autorecon_results`** — walks AutoRecon results; filters targets with no scan data
7. **`parse_loot_dir`** — walks loot directory; Python extractors parse credentials, hashes, file listings
8. **`parse_misc_dir`** — walks misc directory; reads text files for LLM interpretation
9. **`build_operator_notes_lookup`** — reads `## Operator Notes` from existing host notes for feedback into all prompt builders
10. **`build_ollama_prompt` / `build_nessus_ollama_prompt` / `build_burp_ollama_prompt` / `build_autorecon_ollama_prompt` / `build_loot_ollama_prompt` / `build_misc_ollama_prompt`** — assemble structured prompts with grounding rules; Nessus and AutoRecon use two-pass (fact extraction → analysis)
11. **`validate_ai_output`** — post-processing validator that cross-references CVEs, IPs, ports, and hostnames against source data
12. **`create_obsidian_vault`** / **`create_nessus_vault`** / **`create_burp_vault`** / **`create_autorecon_vault`** / **`create_loot_vault`** / **`create_misc_vault`** — writes and merges host notes; `status` and `## Operator Notes` are always preserved on re-run
13. **`_process_deep_dives`** — scans host notes for checked `[x] Investigate:` checkboxes, runs focused LLM analysis, writes results as collapsible callouts, marks `[/]` when complete
14. **`build_canvas`** — full rebuild: Campaign Overview → Priority Targets → scan cards → subnet groups → Next Steps
15. **`export_excel`** — generates `Export.xlsx` with Summary, Nmap, Nessus, Burp, AutoRecon, and Loot sheets

## Incremental Analysis

mAIpper tracks which files have been analyzed via `.maipper_state.json` in the vault directory. On re-run, unchanged files are skipped. Use `--reanalyze` to force a full re-run.

## Interactive Mode

`-i` / `--interactive` starts an interactive session combining file watching, LLM chat, and data drops.

**Commands:**
- `/hosts` — list discovered hosts
- `/status` — assessment summary
- `/refresh` — force re-process all files
- `/paste` — multiline paste (auto-detects IPs, credentials, or saves to misc)
- `+cred user:pass [host_ip]` — add credential to loot
- `/help` — command list
- `<question>` — ask the LLM about the assessment (full vault context injected)
- Empty Enter — check for scan changes + process pending deep dives
- Ctrl+C — exit

## Loot Integration

Assessors drop loot files into `scans/loot/` — credentials, hashes, keys, sensitive files.

**Host association:**
- **Subdirectory:** `loot/10.10.10.5/ftp_listing.txt`
- **Filename prefix:** `loot/10.10.10.5_ftp_creds.txt`
- **Unassociated:** `loot/cracked_hashes.txt` — campaign-level

**Output:** Centralized `Loot/Credentials.md` and `Loot/Hashes.md` with per-host tables. Host notes get lightweight `## Loot` sections with summary stats and links. File listings stay inline.

## Deep Dive Checkboxes

Host notes include `- [ ] Investigate:` checkboxes next to ports (all), Nessus findings (medium+), and Burp issues (high/medium).

**Flow:**
1. `- [ ] Investigate: SMB (tcp/445)` — unchecked, normal
2. `- [x] Investigate: SMB (tcp/445)` — user checked, **yellow highlight** (pending)
3. `- [/] Investigate: SMB (tcp/445)` — mAIpper analyzed, **green highlight** (complete)

Results appear as collapsible callouts in `## Deep Dives`. CSS snippet auto-installed and auto-enabled in `.obsidian/`.

## Operator Notes Feedback Loop

The `## Operator Notes` section in each host note is a live feedback channel. On re-run, notes are injected as `[OPERATOR]` context into ALL prompt builders.

## Host Note Format

```yaml
---
ip: 10.10.10.5
hostnames: ["dc01.domain.local"]
status: not-started        # not-started / in-progress / done / exploited / blocked
tags: ["smb", "kerberos", "ldap", "domain-controller", "autorecon", "loot"]
sources: ["InternalScan - Nmap", "InternalScan - Nessus", "Loot"]
nessus_max_severity: 4
autorecon_tools_run: 15
loot_file_count: 3
loot_credential_count: 5
loot_hash_count: 2
---
```

## Output Layout

```
Obsidian/
├─ .obsidian/snippets/maipper.css   # auto-installed CSS for investigation checkboxes
├─ Hosts/<hostname-or-ip>.md        # frontmatter + ports + findings + deep dives + operator notes
├─ Scans/<scan-name> - Nmap.md      # per-scan note with AI analysis
├─ Scans/<scan-name> - Nessus.md
├─ Scans/<scan-name> - Burp.md
├─ Scans/<target> - AutoRecon.md
├─ Scans/<filename> - Misc.md       # misc tool output with LLM interpretation
├─ Loot/
│   ├─ Overview.md                  # summary, host links, AI analysis
│   ├─ Credentials.md              # all credentials organized by host
│   └─ Hashes.md                   # all hashes organized by host
├─ Assessment Canvas.canvas
└─ Export.xlsx                      # optional; --excel flag
```

## Hallucination Mitigation

1. **Python pre-processing** — structured fact extraction before LLM sees raw data
2. **Prompt grounding rules** — `[CONFIRMED]`/`[INFERRED]`/`[ASSUMED]` tagging, English-only, explicit anti-hallucination instructions
3. **Temperature control** — default 0.15. Adjustable via `--temperature`
4. **Post-processing validator** — cross-references CVEs, IPs, ports, hostnames against source data

Nessus and AutoRecon use **two-pass analysis**: Pass 1 extracts facts, Pass 2 analyzes them.

## Key Conventions

- `safe_filename()` strips characters illegal in Obsidian/Windows filenames.
- Obsidian internal links use `[[Hosts/<stem>|display]]` syntax — no `.md` extension.
- Canvas file node paths are relative to the vault root, forward slashes only.
- Ollama called with `stream: false`; response in `response.json()["response"]`.
- **Versioning**: copy the file and increment the version number for each new version.
- Host association (loot and misc): subdirectory name > filename IP prefix > filename FQDN prefix > campaign-level.
- `--init` creates all scan subdirectories + `maipper.conf`; partial directories auto-completed on every run.

## Prompt Architecture

Seven prompts, each with GROUNDING RULES header (English-only, anti-hallucination):

| Prompt | Function | Key sections |
|--------|----------|--------------|
| Nmap | `build_ollama_prompt` | Environment Assessment, Key Observations, Enumeration Suggestions, Potential Attack Paths, Notable Risks |
| Nessus | `build_nessus_ollama_prompt` | Key Observations, Exploitation Priority, Attack Chains, Remediation Focus |
| Burp | `build_burp_ollama_prompt` | Key Observations, Exploitation Priority, Attack Chains, False Positive Risk, Remediation Focus |
| AutoRecon | `build_autorecon_ollama_prompt` | Key Observations, Service-Specific Findings, Credential & Access Findings, Attack Paths, Manual Follow-Up |
| Loot | `build_loot_ollama_prompt` | Loot Analysis, Credential Impact, Recommended Next Steps |
| Misc | `build_misc_ollama_prompt` | Tool Identification, Key Findings, Notable Items, Recommended Next Steps |
| Deep Dive | `build_deep_dive_prompt` | Attack Surface, Enumeration Commands, Known Vulnerabilities, Attack Paths, Next Steps |
| Priority Targets | `build_priority_targets_prompt` | Numbered ranked list, evidence citation required |
