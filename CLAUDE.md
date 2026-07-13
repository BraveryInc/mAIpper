# CLAUDE.md

This file provides guidance when working with code in this repository.

## What This Is

**mAIpper** is a single-file Python CLI tool (`mAIpper.py`) for pentesters. It ingests scan output from multiple tools, queries a local LLM via **Ollama**, and writes structured **Obsidian notes** (Markdown + Canvas JSON) for use in an Obsidian vault.

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
python mAIpper.py

# Initialize scan directory structure + config file
python mAIpper.py --init

# Interactive mode — fast start (no LLM), analyze on demand
python mAIpper.py -i
python mAIpper.py -i --watch-interval 60
# Then in interactive mode:
#   /analyze       — process checked [x] investigation/analysis boxes
#   /analyze-full  — check all boxes then analyze everything
#   /deepdive      — cross-source correlation per host (## Cross-Source Analysis)
#   /merge         — merge duplicate host notes (IP note + hostname note)

# Single Nmap file
python mAIpper.py --xml scans/nmap/internal.xml

# Skip AI, skip canvas, custom vault output dir
python mAIpper.py --no-ollama --no-canvas --vault MyNotes

# Skip specific parsers
python mAIpper.py --no-nessus --no-burp --no-autorecon --no-loot --no-misc

# Remote Ollama instance, different model
python mAIpper.py --ollama-url http://10.10.10.5:11434 --model llama3:8b

# Export to Excel (requires openpyxl)
python mAIpper.py --excel

# Force re-analysis of all files (ignore incremental state)
python mAIpper.py --reanalyze

# Hallucination mitigation tuning
python mAIpper.py --temperature 0.1    # lower = less creative (default: 0.15)
python mAIpper.py --skip-validation    # bypass post-processing validator

# Verbose / debug logging
python mAIpper.py -v      # INFO
python mAIpper.py -vv     # DEBUG
```

Dependencies beyond stdlib:

```bash
pip install requests          # required
pip install openpyxl          # required only for --excel
pip install pypdf             # required only for RAG with PDFs
```

Ollama must be running locally (`ollama start`) before invoking unless `--no-ollama` is used. Recommended model: `qwen2.5:14b-instruct-q5_K_M`.

## Configuration

`maipper.conf` (INI format) in the working directory. Created by `--init`. CLI flags override config values.

Sections: `[general]` (scans_dir, vault, tool_name, verbose), `[ollama]` (ollama_url, model, temperature), `[canvas]` (canvas_name, canvas_cols, canvas_groups_per_row), `[interactive]` (interactive, watch_interval), `[parsers]` (no_ollama, no_canvas, no_nessus, etc.).

Set `interactive = true` in `[interactive]` to start in interactive mode by default.

## Architecture

Everything lives in `mAIpper.py`. The flow is linear:

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
14. **`_process_analyze_requests`** — scans scan notes for checked `[x] Analyze:` checkboxes, re-parses source files, injects scan-level operator notes, runs scan-type-specific LLM analysis, updates `## Analysis` sections
15. **`_check_all_pending_boxes`** — marks every unchecked `[ ]` investigate/analyze box as `[x]`; used by `/analyze-full`
16. **`build_cross_source_prompt`** / **`_run_cross_source_deepdive`** / **`_write_cross_source_result`** — per-host cross-source correlation: collects all sections from host note, synthesizes in one prompt, writes `## Cross-Source Analysis`
17. **`_detect_and_merge_host_notes`** / **`_merge_two_host_notes`** / **`_replace_vault_host_refs`** — detect duplicate notes (IP + hostname name the same host), merge frontmatter and body sections, rewrite canvas/note links
18. **`build_canvas`** — full rebuild: Campaign Overview → Priority Targets → scan cards → subnet groups → Next Steps
19. **`build_users_canvas`** — builds Users Canvas: credential → host → service relationship graph with confirmed access edges
20. **`_detect_misc_tool`** — auto-detects tool type from filename/content signatures, returns (tool_name, analysis_level)
21. **`_process_injestor`** — parses Injestor drop zone, creates host notes, extracts credentials and standalone usernames, writes to `Loot/Credentials.md`, archives to Scans/, resets page
22. **`_append_injestor_to_credentials_md`** — appends Injestor creds/usernames directly to `Loot/Credentials.md`; deduplicates by username; creates file and Campaign-Level section if needed
23. **`_write_campaign_targets_note`** — generates copy-paste target lists from all vault data
24. **`_build_rag_index`** — chunks PDFs + markdown, embeds via Ollama, stores in SQLite with float16 embeddings
25. **`_rag_retrieve`** / **`_get_rag_context`** — streaming cosine similarity from SQLite with heapq top-k, formats `[REF: source]` blocks for prompt injection
26. **`export_excel`** — generates `Export.xlsx` with Summary, Nmap, Nessus, Burp, AutoRecon, and Loot sheets
27. **`_write_finding_note`** / **`_write_nessus_finding_notes`** / **`_write_burp_finding_notes`** — create/update `Findings/*.md` PlexTrac notes; deduplicate by plugin_id or issue name; merge affected_assets across hosts
28. **`export_plextrac`** — reads all `Findings/*.md`, writes `Findings/PlexTrac Export.csv` matching PlexTrac v3.2 import format
29. **`detect_kiwi_secretsdump`** — detects kiwi/mimikatz/secretsdump output format from text; returns `"sam"`, `"kiwi_sekurlsa"`, `"kiwi_lsa_dump"`, or `None`
30. **`parse_kiwi_secretsdump`** — Python fast-path parser for three kiwi formats: SAM dump lines (`user:RID:LM:NTLM:::`), sekurlsa blocks (`* Username / * NTLM`), and meterpreter lsa_dump_sam (`RID: / User: / Hash NTLM:` blocks); skips empty/null NTLM hashes
31. **`_llm_extract_tool_output`** — LLM-based credential/host extraction for freeform Notes content; temperature 0.05, JSON-only output; results written to `## Pending Review` in the archive note for operator confirmation

## Incremental Analysis

mAIpper tracks which files have been analyzed via `.maipper_state.json` in the vault directory. On re-run, unchanged files are skipped. Use `--reanalyze` to force a full re-run.

## Interactive Mode

`-i` / `--interactive` starts an interactive session. Initial processing is **fast (no LLM)** — all Python parsing, host notes, scan notes, and canvases are generated immediately. LLM analysis is on-demand only.

**Commands:**
- `/hosts` — list discovered hosts
- `/status` — assessment summary
- `/analyze` — analyze checked `[x]` items (investigation checkboxes + scan analysis boxes)
- `/analyze-full` — check ALL unchecked boxes then run full analysis (equivalent to checking everything and running `/analyze`)
- `/deepdive` — cross-source correlation per host: synthesizes Nmap + Nessus + Burp + AutoRecon + Loot into one analysis per host, writes `## Cross-Source Analysis`
- `/merge` — detect and merge duplicate host notes (e.g., `10.10.10.5.md` + `dc01.domain.local.md`)
- `/refresh` — re-process all scan files (no analysis)
- `/paste` — multiline paste (auto-detects IPs, credentials, or saves to misc)
- `+cred user:pass [host_ip]` — add credential to loot
- `/help` — command list
- `<question>` — ask the LLM about the assessment (full vault context injected)
- Empty Enter — check for scan + vault changes, process Injestor, report pending items; if pending items found, prompts `Analyze now? [Y/n]:` (Enter = yes)
- Ctrl+C — cancel current operation / exit at prompt

**Analysis workflow:** Check `[x]` on any investigate checkbox (host notes) or analyze checkbox (scan notes) in Obsidian, then run `/analyze`. The LLM processes only checked items. Investigation results appear as callouts in `## Deep Dives`; scan analysis fills the `## Analysis` section. Checkboxes turn `[/]` (green) when complete.

**Vault change detection:** The watch loop monitors both `scans/` and vault files (`Hosts/*.md`, `Injestor.md`, `Loot/Credentials.md`). On vault changes:
- **Host notes changed** → operator notes reloaded; pending checkboxes reported
- **Injestor.md changed** → Python processing runs (host creation, targets update)
- **Credentials.md changed** → Users Canvas rebuilt
- No LLM calls happen automatically — always explicit via `/analyze`, `/analyze-full`, or `/deepdive`

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
3. Run `/analyze` → LLM re-parses source file, fills `## Analysis` section (scan-level operator notes injected automatically)
4. `- [/] Analyze: Nmap` — complete

Scan analysis checkboxes exist for: Nmap, Nessus, Burp, AutoRecon, Misc, and per-host Loot (`- [ ] Analyze: Loot — {host}`). Injestor archive notes also get a `- [ ] Analyze: Misc` checkbox and a `## Analysis` section.

**`/analyze-full`** — marks every unchecked `[ ]` box across all host notes and scan notes as `[x]`, then runs the full analysis pass. Equivalent to checking everything manually and running `/analyze`.

**Batch mode** (`python mAIpper.py` without `-i`) runs full analysis upfront as before. Checkboxes appear pre-set to `[/]`.

CSS snippet auto-installed in `.obsidian/` for yellow `[x]` and green `[/]` highlighting.

## Operator Notes Feedback Loop

The `## Operator Notes` section in **host notes** is a live feedback channel. On re-run, notes are injected as `[OPERATOR]` context into ALL prompt builders.

**Scan notes also have `## Operator Notes`** — preserved across re-runs. When `/analyze` re-analyzes a scan note, the scan-level operator notes are prepended to the prompt as `[OPERATOR SCAN NOTES]` context, letting you guide per-scan analysis without touching host notes.

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
├─ Injestor.md                     # operator drop zone — paste anything, processed on next run
├─ Scans/<scan-name> - Nmap.md      # per-scan note with AI analysis
├─ Scans/<scan-name> - Nessus.md
├─ Scans/<scan-name> - Burp.md
├─ Scans/<target> - AutoRecon.md
├─ Scans/<filename> - Misc.md       # misc tool output with LLM interpretation
├─ Loot/
│   ├─ Overview.md                  # summary, host links, AI analysis
│   ├─ Credentials.md              # Username | Password | Hash | Hash Type | Source | Notes
│   └─ Hashes.md                   # all hashes organized by host
├─ Assessment Canvas.canvas
├─ Users Canvas.canvas              # credential → host → service graph
├─ Findings/
│   ├─ _Template.md                 # copy in Obsidian to create manual findings
│   ├─ <finding-name>.md            # one note per unique finding (auto from Nessus/Burp, or manual)
│   └─ PlexTrac Export.csv          # generated by --plextrac or /plextrac
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
- **Versioning**: the file is `mAIpper.py` (no version suffix). Increment the version string in the module docstring header, then create a git tag (`git tag vX.Y && git push origin vX.Y`).
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
| Cross-Source | `build_cross_source_prompt` | Correlated Findings, Attack Path Synthesis, Coverage Gaps, Priority Actions |
| Priority Targets | `build_priority_targets_prompt` | Numbered ranked list, evidence citation required |

## Cross-Source Deep Dive

`/deepdive` runs a **cross-source correlation** per host rather than re-running each scanner in isolation. For each host note, it collects all existing sections (Ports, Findings, Loot, Deep Dives, Operator Notes) and passes them to a single prompt: `build_cross_source_prompt`. Output is written to `## Cross-Source Analysis` in the host note.

Sections produced: **Correlated Findings** (connections across tools), **Attack Path Synthesis** (end-to-end chains), **Coverage Gaps** (what's missing), **Priority Actions** (ranked next steps).

`_write_cross_source_result(host_path, analysis)` — inserts or replaces `## Cross-Source Analysis` before `## Scan References` or `## Operator Notes`.

`_run_cross_source_deepdive(vault_dir, args, operator_notes_lookup)` — walks all non-campaign host notes and runs the correlation pass.

## Injestor Page

`Injestor.md` is a drop zone at the vault root. Assessors paste anything — arp tables, host lists, tool output, notes — and on the next mAIpper run (batch or interactive Enter), the content is:

1. **Parsed** for IPs, hostnames, FQDNs, URLs, credentials, and **standalone usernames**
2. **New host notes** created for each IP not already in the vault, with:
   - MAC address (if from arp output)
   - Ready-to-run nmap scan commands in `## Next Steps`
   - `injestor` tag and `Injestor` source
3. **Credentials and usernames written directly to `Loot/Credentials.md`** — both `user:pass` pairs and bare usernames (marked `potential`) are appended to the Campaign-Level section immediately; no separate loot pipeline run needed
4. **Archived** to `Scans/Injestor <timestamp>.md` with links to new/existing hosts, extracted hostnames, a `## Credentials Found` table, a `## Potential Usernames` list, tool detection metadata, `- [ ] Analyze: Misc` checkbox, and the original input in a collapsible block
5. **Campaign Targets** updated with newly discovered IPs/hostnames
6. **Injestor page reset** to blank template for the next drop

Three sections with distinct processing pipelines:

**`## Notes`** — smart detection runs in priority order:
1. **NXC fast-path** — `NXC_STATUS_LINE_RE` match → `parse_nxc_stdout`; goes directly to `Loot/Credentials.md`, no review
2. **Kiwi fast-path** — `detect_kiwi_secretsdump` match → `parse_kiwi_secretsdump`; handles SAM lines, sekurlsa blocks, and meterpreter lsa_dump_sam format; goes directly to `Loot/Credentials.md`, no review
3. **LLM → Pending Review** — freeform/unknown content; `_llm_extract_tool_output` at temperature 0.05; results held in `## Pending Review` in the archive note until operator confirms

**`## Tool Output`** — same smart detection priority order as Notes; NXC and kiwi bypass LLM; anything else adds to the LLM batch

**`## Access`** — access tracking entries written to host note `## Access` tables

`_append_injestor_to_credentials_md(vault_dir, creds, usernames, source_label)` — appends new entries to `Loot/Credentials.md`, creating the file or a `## Campaign-Level` section if needed. Skips duplicates by username (case-insensitive).

Supports arp -a output (Linux and Windows formats), plain IP lists, tool output with embedded IPs/URLs, free-text notes, and credential dumps.

## RAG — Reference Library

Index PDF security books and a local HackTricks clone. Analysis gets cited references injected as `[REF: source]` context.

**Setup:** `pip install pypdf`, `ollama pull nomic-embed-text`, drop PDFs in `docs/`, optionally clone HackTricks into `docs/hacktricks`.

**Index:** `--build-index` CLI flag or `/build-index` in interactive mode. Saves to `.maipper_rag_index.db` (SQLite) in the working directory (not the vault — survives vault rebuilds). Embeddings stored as float16 BLOBs (~half the size of float32). Checkpoints via `conn.commit()` every 200 chunks. Incremental — only re-embeds changed files, cleans up deleted files. WAL mode for concurrent read/write (background builder + retrieval).

**Config** (`[rag]` section in `maipper.conf`): `docs_dir`, `hacktricks_dir`, `embedding_model` (default: `nomic-embed-text`), `max_chunks`, `auto_build` (default: `true` — prompts on startup if unindexed or changed docs found).

**At analysis time:** Embeds query from scan context, streams cosine-similarity search from SQLite with heapq top-k (never loads all embeddings into memory), injects as `[REFERENCE MATERIAL]` block. Nmap gets top 5, deep dives get top 8.

**Optional dependency:** `pypdf` for PDFs (same pattern as `openpyxl`). Markdown files parsed natively. RAG is silently disabled if no index exists and no docs configured.

## PlexTrac Integration

Generates `Findings/` notes compatible with PlexTrac's CSV import format. Each finding note has frontmatter with all PlexTrac fields and a markdown body with `## Description`, `## Recommendations`, and `## References` sections.

**Finding note creation:**
- **Auto (Nessus):** medium+ severity findings → one note per unique plugin; `affected_assets` accumulates all IPs across hosts; enabled by default, skip with `--no-findings`
- **Auto (Burp):** medium+ severity issues → one note per unique issue name; `affected_assets` accumulates all URLs/paths; same `--no-findings` flag
- **Manual:** copy `Findings/_Template.md` in Obsidian, fill in the fields

**Finding note format (frontmatter):** `title`, `severity`, `status` (Draft/Open/Closed/In Review), `affected_assets` (list), `tags` (list), `cvss_temporal`, `cwe`, `cve`, `category`, `sources`

**Deduplication:** keyed by plugin_id (Nessus) or issue name (Burp). On re-run, existing notes are only updated on `affected_assets` — operator edits to description, recommendations, severity, and status are preserved.

**Export:**
- `--plextrac` flag (batch) or `/plextrac` command (interactive) → writes `Findings/PlexTrac Export.csv`
- CSV columns match the PlexTrac v3.2 import format exactly: `title, severity, status, description, recommendations, references, affected_assets, tags, cvss_temporal, cwe, cve, category`
- `description` and `recommendations` pulled from `## Description` / `## Recommendations` body sections; `references` pulled from `## References` as comma-separated list

**Key functions:**
- `_write_finding_note(findings_dir, finding)` — create or update one finding note
- `_write_nessus_finding_notes(vault_dir, nessus_data, scan_source)` — batch from Nessus
- `_write_burp_finding_notes(vault_dir, burp_data, scan_source)` — batch from Burp
- `export_plextrac(vault_dir)` — reads all `Findings/*.md`, writes CSV
- `_install_findings_template(vault_dir)` — creates `Findings/_Template.md` on vault init

## Assessment & Roadmap (v0.13)

### What works well

- **Multi-source ingestion** — Nmap, Nessus, Burp, AutoRecon (10 tool extractors), Loot, Misc (25+ signature detections). Most assessment sources covered.
- **LLM grounding** — CONFIRMED/INFERRED/ASSUMED tagging, two-pass fact-extraction (Nessus, AutoRecon), per-prompt anti-hallucination rules, source truth validation, operator notes feedback loop. Defensive LLM usage throughout.
- **Obsidian as the UI** — host notes, canvases, watch loop, CSS checkbox snippets. Pentesters can live in one tool.
- **Operator notes feedback loop** — `## Operator Notes` in host notes feeds back into every subsequent LLM prompt, making analysis smarter as you add context.
- **`/deepdive` cross-source synthesis** — correlates Nmap + Nessus + Burp + AutoRecon + Loot per host, finds chains that only emerge when viewing all data together. Coverage Gaps section flags missing sources. Standout feature.
- **Incremental state** — `.maipper_state.json` skips unchanged files; `--reanalyze` forces full redo; `/reanalyze` interactive equivalent.
- **PlexTrac integration** — auto-draft findings from Nessus/Burp, dedup by plugin/issue, accumulate affected_assets, export CSV matching PlexTrac v3.2.

### Known gaps (pentest workflow perspective)

**Critical — missing workflow coverage:**
1. **Post-exploitation tracking** — `status: exploited` exists but no structured place for access gained (user, privilege, method, sessions, lateral movement). The kill chain is not tracked.
2. **BloodHound / AD path data** — AD assessments without BloodHound data miss critical attack paths. JSON exports would feed the Users Canvas and host prioritization directly.
3. **Finding descriptions need LLM drafting** — PlexTrac notes are populated with raw Nessus plugin text. Need a `/draft-findings` step that rewrites descriptions as professional report findings using host context.
4. **Evidence collection is freeform** — no structured `## Evidence` section in finding notes; no link from evidence to findings.

**Important — quality and scale:**
5. **Sequential LLM calls don't scale** — 50 hosts × multiple sources = 300+ sequential calls. No parallelization (`concurrent.futures` would fix this).
6. **Finding consolidation is inverted** — dedup by plugin_id is the right default but no way to split findings back out or manually group unrelated ones.
7. **validate_ai_output only checks CVEs** — doesn't validate IP addresses or ports mentioned in analysis against source data. Easy to extend.
8. **Prompts are hardcoded** — no template system for engagement-specific context (client industry, compliance, assessment type), custom output sections, or per-prompt temperature tuning.

**Missing parsers (high-value):**
9. **CrackMapExec** — bulk spray / domain enumeration results; daily-driver tool on internal assessments.
10. **Responder logs** — LLMNR/NBT-NS hash captures.
11. **BloodHound JSON** — shortest paths to DA, kerberoastable accounts, AS-REP targets.
12. **Metasploit db export** — sessions, loot, modules run.

**Architecture / robustness:**
13. **No atomic writes** — interrupted LLM calls during vault writes can corrupt notes. Temp-file-then-rename pattern needed.
14. **String-based section parsing is fragile** — `extract_body_section` breaks if section headers appear inside code blocks or operator notes.
15. **Canvas full rebuild on every run** — slow for large assessments; blows away manual positioning (mitigated by stable node IDs).
16. **No scope tracking** — no in-scope/out-of-scope list, no "confirmed tested" vs "discovered untested" distinction.
17. **Interactive analysis requires Obsidian round-trip** — must check boxes in Obsidian, switch to terminal, run `/analyze`. Want `/analyze <host> <topic>` direct from prompt.
18. **Persistent chat history** — session chat lost on exit; not saved to vault.
19. **Multi-IP host merging** — assets with multiple network interfaces have multiple IPs. Need: (a) `ips` list in frontmatter alongside primary `ip`, (b) `/merge` to detect and collapse notes sharing a hostname even when all three notes have different IPs, (c) canvas and Users Canvas to resolve any IP in the `ips` list to the canonical note. Current `/merge` only matches IP+hostname pairs on a single note, not the three-note case (IP-A.md + IP-B.md + hostname.md all for the same physical host).

### Prioritized next steps

| Priority | Item | Why |
|---|---|---|
| 1 | Exploitation / access tracking | Kill chain is the core of a pentest report; completely missing |
| 2 | BloodHound parser + AD Canvas | Required for internal assessments; pairs with Users Canvas |
| 3 | LLM-assisted finding drafting (`/draft-findings`) | Biggest reporting quality gap; raw plugin text ≠ professional finding |
| 4 | Parallel LLM calls | Biggest performance gap; hours → minutes for large assessments |
| 5 | Evidence blocks in findings | Bridges note-taking and reporting |
| 6 | CrackMapExec + Responder parsers | Daily-driver tools, high return |
| 7 | Scope management | Required for client-facing deliverables |
| 8 | Extend hallucination validator to ports/IPs | Low effort, meaningful accuracy improvement |
| 9 | Atomic vault writes | Robustness; prevents corruption under interruption |
| 10 | `/analyze <host> <topic>` direct command | Removes Obsidian round-trip for active exploitation sessions |
| 11 | Multi-IP host merging | Dual-homed assets produce split notes; `/merge` needs to unify by shared hostname across all IP notes |
