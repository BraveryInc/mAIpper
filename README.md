# mAIpper

A single-file Python CLI for pentesters. Ingests scan output from multiple tools, queries a local LLM via [Ollama](https://ollama.com), and writes structured [Obsidian](https://obsidian.md) notes — host notes, canvas graphs, credential tracking, and on-demand AI analysis organized around the assessment workflow.

---

## What it does

- **Parses** Nmap XML, Nessus, Burp Suite Issues XML, AutoRecon, NetExec (NXC), loot files, and misc tool output into structured Obsidian notes
- **Tracks** credentials, hashes, and loot with per-host association
- **Generates** a visual canvas (Assessment Canvas, Users Canvas) showing host relationships, credential access, and subnet groupings
- **Analyzes** on-demand via Ollama — check a box in Obsidian, run `/analyze`, get LLM deep dives without leaving your notes
- **Correlates** across sources per host with `/deepdive` — finds attack chains that only emerge when Nmap, Nessus, Burp, and Loot are viewed together
- **Exports** to PlexTrac CSV and Excel

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (local or remote — see below)
- [Obsidian](https://obsidian.md) to view the generated vault

---

## Installation

```bash
git clone https://github.com/<your-org>/mAIpper.git
cd mAIpper
pip install -r requirements.txt
```

`requests` is the only required package. `openpyxl` and `pypdf` are optional:

```bash
pip install requests                  # required — Ollama API
pip install openpyxl                  # optional — --excel export
pip install pypdf                     # optional — RAG with PDF reference books
```

---

## Ollama Setup

Ollama provides LLM inference. It can run locally on your assessment machine or on a dedicated remote host — a GPU server shared across the team is the most practical setup for larger engagements.

### Local

```bash
# Install from https://ollama.com/download
ollama serve
ollama pull llama3.1:8b
```

### Remote / Shared GPU Server

On the server, bind Ollama to the network interface:

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
ollama pull llama3.1:70b-instruct-q4_K_M
```

Point mAIpper at it from your assessment machine via `maipper.conf` or CLI flag:

```ini
# maipper.conf
[ollama]
ollama_url = http://<server-ip>:11434
model = llama3.1:70b-instruct-q4_K_M
```

```bash
# Or per-run
python mAIpper.py --ollama-url http://<server-ip>:11434 --model llama3.1:70b-instruct-q4_K_M
```

The vault stays local per operator per engagement. Only the LLM calls go to the remote server.

**Recommended models by available VRAM:**

| VRAM | Model |
|---|---|
| ~6 GB | `llama3.1:8b` (default, Q4_K_M) |
| ~9 GB | `llama3.1:8b-instruct-q8_0` (higher fidelity) |
| ~24 GB | `llama3.1:70b-instruct-q2_K` |
| ~40 GB | `llama3.1:70b-instruct-q4_K_M` |

The default is **Llama 3.1 8B** (`llama3.1:8b`) — a solid all-round local model that runs comfortably on a single mid-range GPU or an Apple Silicon laptop. Larger models produce noticeably better analysis, especially for cross-source correlation and deep dive synthesis.

---

## Quick Start

```bash
# 1. Initialize the directory structure and config file
python mAIpper.py --init

# 2. Drop scan files into the appropriate folders (see Scan Inputs below)

# 3a. Interactive mode — fast start, analyze on demand (recommended)
python mAIpper.py -i

# 3b. Batch mode — parse everything and run LLM analysis upfront
python mAIpper.py

# 4. Open the vault in Obsidian: File → Open Vault → select the Obsidian/ directory
```

**One-time Obsidian setup:** go to **Settings → Appearance → CSS Snippets** and enable `maipper`. This activates checkbox highlighting — yellow for pending analysis, green for complete.

---

## Scan File Inputs

After `--init`, drop files into `scans/`:

```
scans/
├── nmap/           Nmap XML files (*.xml)
├── nessus/         Nessus export files (*.nessus)
├── burp/           Burp Suite Issues XML (*.xml)
├── autorecon/      AutoRecon output directories
├── loot/           Credentials, hashes, keys, sensitive files
│   ├── 10.10.10.5/ Subdirectory name = host-associated loot
│   └── dump.txt    Filename IP prefix, or campaign-level (no prefix)
├── misc/           Any other tool output as text files
│                   25+ tools auto-detected by content signature
└── nxc/            NetExec workspace DBs (smb.db, ldap.db, etc.)
```

**Injestor** — paste anything into `Injestor.md` in the vault root. Processed automatically on the next run or interactive Enter.

`Injestor.md` has three sections:

| Section | What to paste | How it's processed |
|---|---|---|
| `## Notes` | ARP tables, IP lists, quick observations, credential dumps | Smart detection (see below) |
| `## Tool Output` | Raw tool console output (NXC, kiwi, linpeas, etc.) | Smart detection (see below) |
| `## Access` | Access gained entries | Written to host note `## Access` tables |

**Smart detection pipeline** (runs in priority order for both Notes and Tool Output):
1. **NXC** — auto-detected by status-line pattern → Python parser, written to `Loot/Credentials.md` immediately, no review step
2. **Kiwi / mimikatz / secretsdump** — auto-detected by content signatures → Python parser handling three formats: SAM dump lines, sekurlsa blocks, and meterpreter `lsa_dump_sam` output; written to `Loot/Credentials.md` immediately
3. **Freeform / unknown** — sent to LLM at temperature 0.05 for JSON extraction; results land in `## Pending Review` in the archive note for operator confirmation before being added to `Loot/Credentials.md`

---

## Interactive Mode

```bash
python mAIpper.py -i
```

Starts immediately with no LLM calls — all parsing, host notes, and canvases are built from scan data in seconds. LLM analysis is triggered explicitly.

| Command | Action |
|---|---|
| `/analyze` | Process all checked `[x]` boxes (investigations + scan analysis) |
| `/analyze-full` | Check every unchecked box, then run full analysis |
| `/deepdive` | Cross-source correlation per host — synthesizes all sources into one analysis |
| `/nxc` | Import NetExec database from `scans/nxc/` or configured workspace |
| `/merge` | Detect and merge duplicate host notes (IP note + hostname note for same host) |
| `/plextrac` | Export `Findings/` notes to PlexTrac-compatible CSV |
| `/hosts` | List all discovered hosts |
| `/status` | Assessment summary |
| `/chat <question>` | Ask the LLM about the assessment with full vault context injected |
| `/paste` | Multiline paste (auto-detects IPs, credentials, tool output) |
| `/build-index` | Build or update RAG index from `docs/` |
| `+access user@host PRIV METHOD [session] [notes]` | Record a shell or access gained; updates the host note `## Access` section |
| `/access` | Print campaign-wide access summary (all compromised hosts) |
| Enter | Check for new scans and vault changes; prompt to analyze if anything is pending |
| Ctrl+C | Cancel current operation / exit at prompt |

**Analysis workflow:**
1. In Obsidian, check `[x]` on any investigate or analyze checkbox in a host or scan note
2. Back in the terminal, run `/analyze`
3. Results appear as callouts in `## Deep Dives`; checkbox turns `[/]` (green)

---

## NetExec (NXC) Integration

mAIpper imports NXC data from two sources, with DB data winning on conflicts.

**DB import** — direct access to the NXC workspace (e.g., running mAIpper on the same machine as NXC):

```bash
# Auto-discovered if smb.db is dropped into scans/nxc/

# Or point at the live workspace
python mAIpper.py --nxc-workspace ~/.nxc/workspaces/default

# Or set permanently in maipper.conf:
[nxc]
nxc_workspace = ~/.nxc/workspaces/default
```

**Stdout paste** — when NXC runs on a separate machine, paste console output into `Injestor.md`:

```
SMB   10.10.10.5  445  DC01  [+] CORP\administrator:Password123 (Pwn3d!)
SMB   10.10.10.5  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:CORP) (signing:True) (SMBv1:False)
SMB   10.10.10.5  445  DC01  [*] SYSVOL              READ
SMB   10.10.10.5  445  DC01  [*] NETLOGON            READ
```

mAIpper auto-detects NXC output and parses host flags (signing, SMBv1, ZeroLogon, PetitPotam), share enumeration, credentials, and admin access markers. Guest sessions are flagged as null sessions — not added to credentials.

---

## Configuration

`--init` creates `maipper.conf`. CLI flags always override config values.

```ini
[general]
scans_dir = scans
vault = Obsidian
verbose = false

[ollama]
ollama_url = http://localhost:11434
model = llama3.1:8b
temperature = 0.15

[interactive]
interactive = false
watch_interval = 30

[parsers]
no_nessus = false
no_burp = false
no_autorecon = false
no_loot = false
no_misc = false
no_nxc = false

[nxc]
# nxc_workspace = ~/.nxc/workspaces/default

[rag]
docs_dir = docs
hacktricks_dir = docs/hacktricks
embedding_model = nomic-embed-text
max_chunks = 5
auto_build = true
```

---

## Key Flags

```
python mAIpper.py [flags]

  --init                  Create scan directory structure and config file
  -i, --interactive       Interactive mode (fast start, on-demand analysis)
  --ollama-url URL        Ollama endpoint (default: http://localhost:11434)
  --model MODEL           Ollama model name
  --temperature FLOAT     LLM temperature 0.0–1.0 (default: 0.15)
  --workers N             Parallel LLM workers for deep dives and cross-source analysis (default: 1)
  --no-ollama             Skip all LLM analysis (parse and write notes only)
  --no-canvas             Skip canvas generation
  --reanalyze             Force re-analysis of all files (ignore saved state)
  --nxcdb PATH            NetExec workspace directory or smb.db path
  --nxc-workspace DIR     Live NXC workspace (e.g. ~/.nxc/workspaces/default)
  --excel                 Export summary to Excel (requires openpyxl)
  --plextrac              Export Findings/ notes to PlexTrac CSV
  --build-index           Build RAG index from docs/ (requires pypdf)
  --xml FILE              Process a single Nmap XML file
  --vault DIR             Output vault directory (default: Obsidian/)
  --no-nessus             Skip Nessus parser
  --no-burp               Skip Burp parser
  --no-autorecon          Skip AutoRecon parser
  --no-loot               Skip loot parser
  --no-misc               Skip misc parser
  --no-nxc                Skip NXC parser
  --skip-validation       Bypass post-processing hallucination validator
  -v / -vv                Verbose / debug logging
```

---

## Output Layout

```
Obsidian/
├── Hosts/<ip-or-hostname>.md       Per-host notes: ports, findings, deep dives, operator notes
├── Hosts/_Campaign Targets.md      Copy-paste target lists (IPs, subnets, hostnames, /etc/hosts)
├── Injestor.md                     Drop zone — paste anything here
├── Scans/<name> - Nmap.md          Per-scan notes with AI analysis
├── Scans/<name> - Nessus.md
├── Scans/<name> - Burp.md
├── Scans/<target> - AutoRecon.md
├── Scans/<filename> - Misc.md
├── Loot/
│   ├── Credentials.md              All credentials with host association and operator notes
│   └── Hashes.md                   All hashes organized by host
├── Findings/
│   ├── _Template.md                Copy in Obsidian to create manual findings
│   ├── <finding>.md                Auto-drafted from Nessus/Burp, or created manually
│   └── PlexTrac Export.csv         Generated by --plextrac or /plextrac
├── Assessment Canvas.canvas        Host graph: subnet groups, severity, priority targets
└── Users Canvas.canvas             Credential → host → service relationship graph
```

---

## Credential Tracking

`Loot/Credentials.md` consolidates all credentials across sources. Host-associate loot via subdirectory or filename prefix:

```
scans/loot/
├── 10.10.10.5/sam_dump.txt      → associated with 10.10.10.5 (subdirectory)
├── dc01_creds.txt               → associated with dc01 (short hostname prefix)
├── dc01.domain.local_dump.txt   → associated with dc01.domain.local (FQDN prefix)
└── 10.10.10.10_creds.txt        → associated with 10.10.10.10 (IP prefix)
```

Unassociated files go to Campaign-Level. Credential rows in Campaign-Level are automatically re-attributed if the **Notes column** contains a known host identifier — short notes (`dc01`) or prose (`from the SMB share on dc01 with guest read`) both work. mAIpper detects the change on the next Enter press and moves the row to the correct host section.

Mark confirmed access in `Loot/Credentials.md` under any host's `### Operator Notes` section:

```markdown
- [x] Confirmed on 10.10.10.5
- Works on dc01 via RDP only
```

mAIpper scans operator notes on every Credentials.md change. If a known host identifier appears in freeform text, `- [x] Confirmed on <host>` is auto-appended. Ambiguous notes go to the LLM for interpretation (console suggestion only — operator confirms). Confirmed entries create green edges in the Users Canvas.

**Multi-interface hosts** — hosts with multiple IPs store secondary addresses in `ips` frontmatter. Both IPs then resolve to the same host note for loot attribution, canvas layout, and `/merge` detection:

```yaml
ip: 10.10.100.100
ips: ["172.16.1.100"]
hostnames: ["dante-web-nix01"]
```

`/merge` collapses separate IP notes into one canonical note and populates `ips` automatically.

---

## RAG — Reference Your Library

Index PDF security books and a local HackTricks clone. Analysis gets cited references injected as `[REF: source]` context.

```bash
pip install pypdf
ollama pull nomic-embed-text

# Drop PDFs into docs/, optionally clone HackTricks
git clone https://github.com/HackTricks-wiki/hacktricks docs/hacktricks

# Build the index
python mAIpper.py --build-index
```

The index saves to `.maipper_rag_index.db` (SQLite) in the working directory and survives vault rebuilds. Only re-embeds changed files on subsequent builds.

---

## Hallucination Mitigation

- Python pre-parsing extracts structured facts before the LLM sees raw data
- Prompts require `[CONFIRMED]` / `[INFERRED]` / `[ASSUMED]` tagging on all claims
- Default temperature of 0.15 — lower than typical chat usage
- Post-processing validator cross-references CVEs, IPs, and hostnames against source data
- Nessus and AutoRecon use two-pass analysis: fact extraction first, then synthesis

---

## Dependencies

| Package | Required | Purpose |
|---|---|---|
| `requests` | Yes | Ollama API calls |
| `openpyxl` | No | `--excel` export |
| `pypdf` | No | RAG with PDF reference books |

All other dependencies are Python standard library (sqlite3, xml, pathlib, etc.).
