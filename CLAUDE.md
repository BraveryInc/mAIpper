# CLAUDE.md

This file provides guidance when working with code in this repository.

## What This Is

**mAIpper** is a single-file Python CLI tool (`mAIpper-v0.11.py`) for pentesters. It ingests scan output from multiple tools, queries a local LLM via **Ollama**, and writes structured **Obsidian notes** (Markdown + Canvas JSON) for use in an Obsidian vault.

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
# Basic usage — processes all scan files with full LLM analysis
python mAIpper-v0.11.py

# Initialize scan directory structure + config file
python mAIpper-v0.11.py --init

# Interactive mode — fast start (no LLM), analyze on demand
python mAIpper-v0.11.py -i
python mAIpper-v0.11.py -i --watch-interval 60
# Then in interactive mode:
#   /analyze   — process checked [x] investigation/analysis boxes
#   /deepdive  — full LLM analysis of all scans

# Single Nmap file
python mAIpper-v0.11.py --xml scans/nmap/internal.xml

# Skip AI, skip canvas, custom vault output dir
python mAIpper-v0.11.py --no-ollama --no-canvas --vault MyNotes

# Skip specific parsers
python mAIpper-v0.11.py --no-nessus --no-burp --no-autorecon --no-loot --no-misc

# Remote Ollama instance, different model
python mAIpper-v0.11.py --ollama-url http://10.10.10.5:11434 --model llama3:8b

# Export to Excel (requires openpyxl)
python mAIpper-v0.11.py --excel

# Force re-analysis of all files (ignore incremental state)
python mAIpper-v0.11.py --reanalyze

# Hallucination mitigation tuning
python mAIpper-v0.11.py --temperature 0.1    # lower = less creative (default: 0.15)
python mAIpper-v0.11.py --skip-validation    # bypass post-processing validator

# Verbose / debug logging
python mAIpper-v0.11.py -v      # INFO
python mAIpper-v0.11.py -vv     # DEBUG
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

Everything lives in `mAIpper-v0.11.py`. The flow is linear:

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
14. **`_process_analyze_requests`** — scans scan notes for checked `[x] Analyze:` checkboxes, re-parses source files, runs scan-type-specific LLM analysis, updates `## Analysis` sections
15. **`build_canvas`** — full rebuild: Campaign Overview → Priority Targets → scan cards → subnet groups → Next Steps
16. **`build_users_canvas`** — builds Users Canvas: credential → host → service relationship graph with confirmed access edges
17. **`_detect_misc_tool`** — auto-detects tool type from filename/content signatures, returns (tool_name, analysis_level)
18. **`_process_eat_me_page`** — parses Eat Me drop zone, creates host notes, archives to Scans/, resets page
19. **`_write_campaign_targets_note`** — generates copy-paste target lists from all vault data
20. **`export_excel`** — generates `Export.xlsx` with Summary, Nmap, Nessus, Burp, AutoRecon, and Loot sheets

## Incremental Analysis

mAIpper tracks which files have been analyzed via `.maipper_state.json` in the vault directory. On re-run, unchanged files are skipped. Use `--reanalyze` to force a full re-run.

## Interactive Mode

`-i` / `--interactive` starts an interactive session. Initial processing is **fast (no LLM)** — all Python parsing, host notes, scan notes, and canvases are generated immediately. LLM analysis is on-demand only.

**Commands:**
- `/hosts` — list discovered hosts
- `/status` — assessment summary
- `/analyze` — analyze checked `[x]` items (investigation checkboxes + scan analysis boxes)
- `/deepdive` — full LLM analysis of all scans (equivalent to batch mode)
- `/refresh` — re-process all scan files (no analysis)
- `/paste` — multiline paste (auto-detects IPs, credentials, or saves to misc)
- `+cred user:pass [host_ip]` — add credential to loot
- `/help` — command list
- `<question>` — ask the LLM about the assessment (full vault context injected)
- Empty Enter — check for scan + vault changes, process Eat Me, report pending analysis items
- Ctrl+C — cancel current operation / exit at prompt

**Analysis workflow:** Check `[x]` on any investigate checkbox (host notes) or analyze checkbox (scan notes) in Obsidian, then run `/analyze`. The LLM processes only checked items. Investigation results appear as callouts in `## Deep Dives`; scan analysis fills the `## Analysis` section. Checkboxes turn `[/]` (green) when complete.

**Vault change detection:** The watch loop monitors both `scans/` and vault files (`Hosts/*.md`, `Eat Me.md`, `Loot/Credentials.md`). On vault changes:
- **Host notes changed** → operator notes reloaded; pending checkboxes reported
- **Eat Me.md changed** → Python processing runs (host creation, targets update)
- **Credentials.md changed** → Users Canvas rebuilt
- No LLM calls happen automatically — always explicit via `/analyze` or `/deepdive`

## Loot Integration

Assessors drop loot files into `scans/loot/` — credentials, hashes, keys, sensitive files.

**Host association:**
- **Subdirectory:** `loot/10.10.10.5/ftp_listing.txt`
- **Filename prefix:** `loot/10.10.10.5_ftp_creds.txt`
- **Unassociated:** `loot/cracked_hashes.txt` — campaign-level

**Output:** Centralized `Loot/Credentials.md` and `Loot/Hashes.md` with per-host tables. Host notes get lightweight `## Loot` sections with summary stats and links. File listings stay inline.

## Credential Annotations

`Loot/Credentials.md` includes `### Operator Notes` sections under each host's credential table. These are preserved across re-runs.

**Confirmed access syntax** — used by the Users Canvas:
- `- [x] Confirmed on 10.10.10.5` — marks confirmed access, creates green edge in Users Canvas
- `- [x] Works on 10.10.10.5` — alternate syntax, same effect
- Free-text notes are also preserved (e.g., "svc_sql also works on MSSQL")

## Users Canvas

`Users Canvas.canvas` visualizes credential → host relationships. Generated from loot data + credential annotations. Skip with `--no-users-canvas`.

**Layout:**
- Left side: user nodes grouped by **source host** (where the credential was found), not account type
- Right side: host file nodes grouped by subnet
- Each user node shows: source file, cred type, and inline Notes from the Credentials.md table
- Nodes are dynamically sized to fit their content
- Edges: standard edges show where credentials were found (labeled with cred type + notes); green edges show operator-confirmed access

**Edge labels** include the Notes column content, e.g. `cleartext · Verified - SMB + RDP` or `cleartext · DB only on this server`.

## Campaign Targets Note

`Hosts/_Campaign Targets.md` is auto-generated on every run. Contains copy-paste-ready target lists:
- **IPs** — all discovered IPs, sorted numerically
- **Subnets** — all /24 subnets seen
- **Hostnames** — all FQDNs from host notes, loot files, and misc files
- **Domains / URLs** — web-only domains not already in Hostnames

Each list is in a fenced code block for easy copy-paste into tools.

## Smarter Misc Analysis

`parse_misc_dir` auto-detects the tool that produced each misc file via `_detect_misc_tool()`. Detection uses filename hints and content signature matching against 25+ tools.

**Analysis levels:**
- **full** — recognized tool with 2+ signature matches. Full LLM prompt with tool-specific hints.
- **standard** — partial match or unknown tool. Standard LLM prompt.
- **minimal** — detected as notes/todo/free-text. Short LLM prompt extracting only key facts (IPs, creds, versions). Saves LLM tokens and time.

**Detected tools include:** nikto, gobuster, dirb, dirsearch, feroxbuster, ffuf, wpscan, linpeas, winpeas, enum4linux, smbmap, smbclient, nmap, masscan, hydra, crackmapexec, bloodhound, impacket, kerbrute, nuclei, testssl, ldapsearch, and more.

Scan notes show `Detected tool:` and `Analysis level:` metadata.

## On-Demand Analysis

Interactive mode starts with **no LLM analysis**. All structured data is generated by Python instantly. Analysis is triggered explicitly:

**Investigation checkboxes** (in host notes) — next to ports, Nessus findings (medium+), Burp issues (high/medium):
1. `- [ ] Investigate: SMB (tcp/445)` — unchecked, normal
2. `- [x] Investigate: SMB (tcp/445)` — user checked, **yellow highlight** (pending)
3. Run `/analyze` → LLM generates deep dive
4. `- [/] Investigate: SMB (tcp/445)` — **green highlight** (complete), results in `## Deep Dives`

**Scan analysis checkboxes** (in scan notes) — one per scan note:
1. `- [ ] Analyze: Nmap` — unchecked
2. `- [x] Analyze: Nmap` — user checked
3. Run `/analyze` → LLM re-parses source file, fills `## Analysis` section
4. `- [/] Analyze: Nmap` — complete

Scan analysis checkboxes exist for: Nmap, Nessus, Burp, AutoRecon, Misc, and per-host Loot (`- [ ] Analyze: Loot — {host}`).

**Batch mode** (`python mAIpper-v0.11.py` without `-i`) runs full analysis upfront as before. Checkboxes appear pre-set to `[/]`.

CSS snippet auto-installed in `.obsidian/` for yellow `[x]` and green `[/]` highlighting.

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
├─ Hosts/_Campaign Targets.md       # copy-paste target lists (IPs, subnets, hostnames, domains)
├─ Eat Me.md                       # operator drop zone — paste anything, processed on next run
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
├─ Users Canvas.canvas              # credential → host → service graph
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
| Misc (full/standard) | `build_misc_ollama_prompt` | Tool Identification (auto-detected or ask LLM), Key Findings, Notable Items, Recommended Next Steps; tool-specific hints for 25+ tools |
| Misc (minimal) | `_build_misc_minimal_prompt` | Key Facts only (IPs, creds, versions); used for notes/todo files |
| Deep Dive | `build_deep_dive_prompt` | Attack Surface, Enumeration Commands, Known Vulnerabilities, Attack Paths, Next Steps |
| Priority Targets | `build_priority_targets_prompt` | Numbered ranked list, evidence citation required |

## Eat Me Page

`Eat Me.md` is a drop zone at the vault root. Assessors paste anything — arp tables, host lists, tool output, notes — and on the next mAIpper run (batch or interactive Enter), the content is:

1. **Parsed** for IPs, hostnames, FQDNs, URLs, and credentials
2. **New host notes** created for each IP not already in the vault, with:
   - MAC address (if from arp output)
   - Ready-to-run nmap scan commands in `## Next Steps`
   - `eat-me` tag and `Eat Me` source
3. **Archived** to `Scans/Eat Me <timestamp>.md` with links to new/existing hosts, extracted hostnames, and the original input in a collapsible block
4. **Campaign Targets** updated with newly discovered IPs/hostnames
5. **Eat Me page reset** to blank template for the next drop

Supports arp -a output (Linux and Windows formats), plain IP lists, tool output with embedded IPs/URLs, and free-text notes.
