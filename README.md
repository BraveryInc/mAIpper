# mAIpper

**mAIpper** is a pentesting workflow tool that ingests scan output, analyzes it with a local LLM via **Ollama**, and generates structured **Obsidian notes and Canvas visualizations** — with optional **RAG** for cited references from your cybersecurity library.

The goal is to automatically convert reconnaissance output into **organized operator notes and attack-path suggestions** with a human-in-the-loop feedback cycle.

Currently supported:

- **Nmap XML scans** — network reconnaissance
- **Nessus** — vulnerability scanning
- **Burp Suite** — web application scanning
- **AutoRecon** — automated multi-tool enumeration
- **Loot** — operator-collected evidence (credentials, hashes, keys, sensitive files)
- **Misc** — arbitrary tool text output for LLM interpretation
- **RAG** — reference your PDF books and HackTricks for cited analysis

---

# Features

- Parse **Nmap XML**, **Nessus**, **Burp Suite**, and **AutoRecon** output
- Ingest **operator-collected loot** (credentials, hashes, file listings) into centralized Loot pages
- Process **miscellaneous tool output** with auto-detected tool type (25+ tools recognized)
- Generate **per-host notes** in Obsidian with merged findings from all sources
- **On-demand analysis** — interactive mode starts fast (no LLM), analyze only what you check
- **Investigation checkboxes** — check a box next to any port or finding to trigger detailed analysis
- **Scan analysis checkboxes** — check a box on any scan note to request LLM analysis; scan-level operator notes injected into prompt automatically
- **`/analyze-full`** — check all unchecked boxes and analyze everything in one command
- **`/deepdive` cross-source correlation** — synthesizes Nmap + Nessus + Burp + AutoRecon + Loot per host into `## Cross-Source Analysis`
- **Duplicate host note merging** — auto-detects when an IP note and hostname note refer to the same host; merges frontmatter, body, and canvas links
- **RAG integration** — index your PDF security books and HackTricks clone for cited references in analysis
- Produce **AI-assisted analysis** using Ollama with hallucination mitigation
- **Operator Notes feedback loop** — manual observations in host notes and scan notes feed back into AI analysis
- **Eat Me page** — paste anything (arp tables, tool output, host lists, usernames, credentials); IPs, creds, and standalone usernames extracted immediately to `Loot/Credentials.md`
- **Campaign Targets** — auto-generated copy-paste target lists (IPs, subnets, hostnames, /etc/hosts)
- **Users Canvas** — credential → host relationship graph with confirmed access edges
- **Assessment Canvas** — campaign overview, priority targets, subnet grouping
- **Nmap port merge** — overlapping scans consolidated, richest service info kept
- **Vault change detection** — watches Obsidian for operator edits in real time
- **Excel export** with per-scanner sheets and severity color-coding

---

# Requirements

- Python **3.10+**
- **Ollama** running locally (or remote via `--ollama-url`)
- An LLM model installed

```bash
pip install requests          # required
pip install openpyxl          # required only for --excel
pip install pypdf             # required only for RAG with PDFs
```

Recommended models:

```bash
ollama pull qwen2.5:14b-instruct-q5_K_M    # chat/analysis
ollama pull nomic-embed-text                 # RAG embeddings
```

---

# Quick Start

```bash
# Initialize directory structure
python mAIpper-v0.12.py --init

# Drop scan files into scans/ subdirectories, then:
python mAIpper-v0.12.py -i
```

Interactive mode starts instantly with Python-only processing. Use commands to control analysis:

| Command | Description |
|---------|-------------|
| `/analyze` | Analyze checked `[x]` items (investigation + scan boxes) |
| `/analyze-full` | Check ALL unchecked boxes then run full analysis |
| `/deepdive` | Cross-source correlation per host → `## Cross-Source Analysis` |
| `/merge` | Detect and merge duplicate host notes (IP + hostname → one note) |
| `/refresh` | Re-process all scan files (no analysis) |
| `/hosts` | List discovered hosts |
| `/status` | Assessment summary |
| `/rag` | Show RAG index status |
| `/build-index` | Build or update RAG index |
| `/paste` | Paste multiline data (hosts, creds, tool output) |
| `+cred u:p` | Add credential (`+cred user:pass [host_ip]`) |
| `<question>` | Ask the LLM about the assessment |
| Enter | Check for changes; if pending items found, prompt `Analyze now? [Y/n]:` |
| Ctrl+C | Cancel current operation / exit at prompt |

---

# Scan Directory Layout

Use `--init` to auto-create the structure:

```
project/
├─ mAIpper-v0.12.py
├─ maipper.conf
├─ docs/                          ← PDF reference books for RAG
│   └─ hacktricks/                ← git clone HackTricks here
├─ scans/
│   ├─ nmap/*.xml
│   ├─ nessus/*.nessus
│   ├─ burp/*.xml
│   ├─ nikto/
│   ├─ autorecon/<target>/scans/
│   ├─ loot/
│   └─ misc/
├─ .maipper_rag_index.json        ← RAG index (auto-generated)
└─ .maipper_state.json            ← incremental state (in vault)
```

---

# Output Structure

```
Obsidian/
├─ Hosts/
│   ├─ _Campaign Targets.md       ← copy-paste target lists
│   ├─ dc01.domain.local.md
│   └─ web01.domain.local.md
├─ Scans/
│   ├─ InternalScan - Nmap.md
│   ├─ InternalScan - Nessus.md
│   └─ linpeas_output - Misc.md
├─ Loot/
│   ├─ Overview.md
│   ├─ Credentials.md             ← separate Password/Hash/Type columns
│   └─ Hashes.md
├─ Eat Me.md                      ← operator drop zone
├─ Assessment Canvas.canvas
├─ Users Canvas.canvas             ← credential → host graph
└─ Export.xlsx
```

---

# On-Demand Analysis

Interactive mode starts with **no LLM analysis** — all structured data generates instantly.

**Investigation checkboxes** (in host notes):
1. `- [ ] Investigate: SMB (tcp/445)` — unchecked
2. Check `[x]` in Obsidian → run `/analyze` → deep dive generated
3. `- [/] Investigate: SMB (tcp/445)` — complete (green highlight)

**Scan analysis checkboxes** (in scan notes):
1. `- [ ] Analyze: Nmap` — unchecked
2. Check `[x]` → run `/analyze` → `## Analysis` section filled by LLM (scan operator notes auto-injected)
3. `- [/] Analyze: Nmap` — complete

**`/analyze-full`** — checks every `[ ]` box across all host notes and scan notes, then runs the full analysis pass. One command to analyze everything that hasn't been looked at.

**`/deepdive`** — reads all existing sections in each host note (ports, findings, loot, deep dives) and runs a single synthesis prompt per host. Writes `## Cross-Source Analysis` with correlated findings, attack chains, coverage gaps, and priority actions. Does not re-run individual scanners — works from what's already in the vault.

**Batch mode** (`python mAIpper-v0.12.py` without `-i`) runs full analysis upfront.

---

# RAG — Reference Your Library

Index your cybersecurity PDF books and a local HackTricks clone so LLM analysis includes cited references.

### Setup

```bash
pip install pypdf
ollama pull nomic-embed-text

# Drop PDFs into docs/
cp ~/books/RTFM.pdf docs/
cp ~/books/PNPT-notes.pdf docs/

# Clone HackTricks
cd docs/
git clone https://github.com/HackTricks-wiki/hacktricks
cd ..

# Build the index
python mAIpper-v0.12.py --build-index
```

Or in interactive mode, mAIpper detects unindexed docs and prompts:
```
[*] RAG: Found 15 PDFs, 2000 HackTricks pages not yet indexed.
    Build index now in background? (y/n): y
[*] RAG: Building index in background — you can work while it runs.
```

### How It Works

- Index builds once, saves to `.maipper_rag_index.json` (survives vault rebuilds)
- Checkpoints every 200 chunks — Ctrl+C preserves progress
- At analysis time: embeds the query, finds relevant chunks, injects as `[REF: source]` context
- LLM cites references: `[REF: RTFM p.142]`, `[REF: HackTricks/windows/privilege-escalation/juicy-potato]`
- Check progress anytime with `/rag`

### Config

```ini
[rag]
docs_dir = docs
hacktricks_dir = docs/hacktricks
embedding_model = nomic-embed-text
max_chunks = 5
auto_build = true
```

---

# Eat Me Page

`Eat Me.md` is a drop zone at the vault root. Paste anything — arp tables, tool output, host lists, credentials, bare usernames — and on next run:

1. IPs, hostnames, credentials, and **standalone usernames** extracted by Python
2. **Credentials and potential usernames written immediately to `Loot/Credentials.md`** — no separate loot pipeline needed
3. New host notes created with ready-to-run nmap scan commands
4. Content archived to `Scans/` with tool detection, `## Credentials Found`, `## Potential Usernames`, and a `- [ ] Analyze: Misc` checkbox
5. Campaign Targets updated
6. Eat Me page reset for next use

---

# Credentials & Users

`Loot/Credentials.md` has separate columns for Username, Password, Hash, Hash Type, Source, and Notes.

- Inline notes stripped from passwords (e.g., `password - (db only)` → password + note)
- Standalone usernames extracted from context blocks in loot files **and from Eat Me pastes**
- Hash types auto-identified (NTLM, SHA-256, SHA-512, bcrypt, etc.)
- Per-credential Notes column preserved across re-runs
- Content-based host association — mentions of hostnames in loot files associate creds with hosts
- **Eat Me direct write** — paste a username list or credential dump into Eat Me and it's immediately appended to `Loot/Credentials.md` (Campaign-Level section); bare usernames marked `(potential)`
- Confirmed access annotations (`- [x] Confirmed on 10.10.10.5`) create green edges in Users Canvas

**Users Canvas** visualizes credential → host relationships grouped by source host.

---

# Loot Workflow

```bash
# Host-associated (subdirectory or filename prefix)
echo "admin:P@ssw0rd" > scans/loot/10.10.10.5/creds.txt

# Campaign-wide
hashcat -m 1000 hashes.txt rockyou.txt --show > scans/loot/cracked.txt
```

mAIpper parses credentials, hashes, file listings, and standalone usernames. Content-based host association resolves hosts from prose mentions ("verified creds for the server DANTE-WEB-NIX01").

---

# Campaign Targets

`Hosts/_Campaign Targets.md` — auto-generated, copy-paste-ready:

- **IPs** — all discovered, sorted numerically
- **Subnets** — all /24s seen
- **Hostnames** — from host note frontmatter only (no noise)
- **/etc/hosts** — tab-separated IP→hostname entries

---

# Hallucination Mitigation

1. **Python pre-processing** — structured fact extraction before LLM sees raw data
2. **Prompt grounding rules** — `[CONFIRMED]`/`[INFERRED]`/`[ASSUMED]` tagging required
3. **Low temperature** — default 0.15 for deterministic output
4. **Post-processing validation** — cross-references CVEs, IPs, ports against source data
5. **RAG grounding** — references from your own library replace model hallucinations

---

# Command Line Options

| Option | Description |
|--------|-------------|
| `--init` | Initialize directory structure and exit |
| `-i`, `--interactive` | Interactive mode (fast start, on-demand analysis) |
| `--build-index` | Build or update RAG index and exit |
| `--no-rag` | Disable RAG context injection |
| `--rag-docs-dir DIR` | PDF reference books directory (default: `docs`) |
| `--rag-hacktricks-dir DIR` | HackTricks markdown clone directory |
| `--rag-embedding-model` | Embedding model (default: `nomic-embed-text`) |
| `--reanalyze` | Force re-analysis of all files |
| `--no-ollama` | Skip all AI analysis |
| `--no-canvas` | Skip canvas generation |
| `--no-users-canvas` | Skip Users Canvas |
| `--excel` | Generate Export.xlsx |
| `--temperature` | Sampling temperature (default: 0.15) |
| `-v` / `-vv` | INFO / DEBUG logging |

---

# Workflow Example

```bash
# 1. Initialize
python mAIpper-v0.12.py --init

# 2. Set up RAG (optional)
pip install pypdf
ollama pull nomic-embed-text
# Drop PDFs into docs/, clone HackTricks into docs/hacktricks
python mAIpper-v0.12.py --build-index

# 3. Start interactive mode
python mAIpper-v0.12.py -i

# 4. Run scans in another terminal
nmap -sC -sV -oX scans/nmap/internal.xml 10.10.10.0/24

# 5. mAIpper auto-detects new files and generates vault
#    Open Obsidian and browse findings

# 6. Check investigation boxes on interesting ports/findings
#    Run /analyze to get detailed analysis with RAG references

# 7. Paste arp tables or tool output into Eat Me.md
#    Press Enter — new hosts created with scan commands

# 8. Add operator notes as you work — they feed into future analysis
```

---
