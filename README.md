# mAIpper

**mAIpper** is a pentesting workflow tool that ingests scan output, analyzes it with a local LLM via **Ollama**, and generates structured **Obsidian notes and Canvas visualizations**.

The goal is to automatically convert reconnaissance output into **organized operator notes and attack-path suggestions** with a human-in-the-loop feedback cycle.

Currently supported:

- **Nmap XML scans** — network reconnaissance
- **Nessus** — vulnerability scanning
- **Burp Suite** — web application scanning
- **AutoRecon** — automated multi-tool enumeration
- **Loot** — operator-collected evidence (credentials, hashes, keys, sensitive files)
- **Misc** — arbitrary tool text output for LLM interpretation

---

# Features

- Parse **Nmap XML**, **Nessus**, **Burp Suite**, and **AutoRecon** output
- Ingest **operator-collected loot** (credentials, hashes, file listings) into centralized Loot pages
- Process **miscellaneous tool output** with LLM interpretation
- Generate **per-host notes** in Obsidian with merged findings from all sources
- **Deep dive checkboxes** — check a box next to any port or finding to trigger detailed analysis on next run
- Produce **AI-assisted analysis** using Ollama with hallucination mitigation
- **Operator Notes feedback loop** — manual observations feed back into AI analysis on re-runs
- **Watch mode** — polls for new scan files and auto-processes
- Suggest **enumeration tools and attack paths** with ready-to-run commands
- Automatically create an **Obsidian Canvas visualization** with campaign overview, priority targets, and subnet grouping
- **Excel export** with per-scanner sheets and severity color-coding
- **Priority Targets** ranking based on CVEs, services, loot, and operator notes

---

# Requirements

- Python **3.10+**
- **Ollama** running locally (or remote via `--ollama-url`)
- An LLM model installed

```bash
pip install requests          # required
pip install openpyxl          # required only for --excel
```

Recommended model:

```
qwen2.5:14b-instruct-q5_K_M
```

---

# Install Ollama

Install Ollama: https://ollama.com

After installation, download the recommended model:

```bash
ollama pull qwen2.5:14b-instruct-q5_K_M
```

Start Ollama:

```bash
ollama start
```

---

# Scan Directory Layout

Place scan output in a `scans` directory in the working folder. Use `--init` to auto-create the structure:

```bash
python mAIpper-v0.10.py --init
```

```
project/
├─ mAIpper-v0.10.py
├─ scans/
│   ├─ nmap/
│   │   ├─ internal.xml
│   │   └─ external.xml
│   ├─ nessus/
│   │   └─ internal_scan.nessus
│   ├─ burp/
│   │   └─ webapp_issues.xml
│   ├─ nikto/
│   │   └─ webapp_nikto.txt
│   ├─ autorecon/
│   │   └─ 10.10.10.5/
│   │       └─ scans/
│   │           ├─ xml/
│   │           ├─ tcp80/
│   │           └─ tcp445/
│   ├─ loot/
│   │   ├─ 10.10.10.5/
│   │   │   ├─ ftp_listing.txt
│   │   │   └─ creds.txt
│   │   ├─ 10.10.10.10_smb_shares.txt
│   │   └─ cracked_hashes.txt
│   └─ misc/
│       ├─ linpeas_output.txt
│       └─ 10.10.10.5/
│           └─ gobuster_results.txt
```

Supported formats:
- `scans/nmap/*.xml` — Nmap XML output
- `scans/nessus/*.nessus` — Nessus scan exports
- `scans/burp/*.xml` — Burp Suite Issues XML
- `scans/nikto/` — Nikto scan output
- `scans/autorecon/<target>/scans/` — AutoRecon results
- `scans/loot/` — Loot files (credentials, hashes, keys)
- `scans/misc/` — Any tool's text output

---

# Running mAIpper

Basic usage:

```bash
python mAIpper-v0.10.py
```

This will:

1. Load operator notes from existing vault (feedback loop)
2. Parse all scans (Nmap, Nessus, Burp, AutoRecon)
3. Parse loot files and extract credentials/hashes
4. Process misc tool output
5. Send summarized data to Ollama for AI analysis
6. Validate AI output for hallucinations
7. Process deep dive requests (checked investigation boxes)
8. Generate Obsidian host notes, scan notes, Loot pages, and canvas
9. Optionally export to Excel

Interactive mode — watch for changes, chat with LLM, drop data:

```bash
python mAIpper-v0.10.py -i
python mAIpper-v0.10.py -i --watch-interval 60
```

Unchanged files are automatically skipped (incremental analysis). Use `--reanalyze` to force a full re-run.

## Configuration

`--init` creates a `maipper.conf` file with all defaults. Edit to set your model, vault path, temperature, etc. CLI flags always override config values.

```bash
python mAIpper-v0.10.py --init   # creates maipper.conf + scans/ structure
```

---

# Output Structure

```
Obsidian/
├─ Hosts/
│   ├─ 10.10.10.5.md
│   ├─ dc01.domain.local.md
│   └─ web01.domain.local.md
├─ Scans/
│   ├─ InternalScan - Nmap.md
│   ├─ InternalScan - Nessus.md
│   ├─ WebApp - Burp.md
│   ├─ 10.10.10.5 - AutoRecon.md
│   └─ linpeas_output - Misc.md
├─ Loot/
│   ├─ Overview.md
│   ├─ Credentials.md
│   └─ Hashes.md
├─ Assessment Canvas.canvas
└─ Export.xlsx
```

Host notes include:
- Open ports and service information (with investigation checkboxes)
- Nessus vulnerability findings (severity-sorted, with investigation checkboxes)
- Burp Suite web findings (with investigation checkboxes)
- AutoRecon enumeration data (technologies, shares, users)
- Loot summary (with links to centralized Loot pages)
- Deep Dives (collapsible analysis results from checked investigation boxes)
- Scan references (links to scan notes)
- Operator Notes (manually editable, feeds back into AI)

---

# Loot Workflow

During an engagement, drop collected evidence into `scans/loot/`:

```bash
# Associate loot with a specific host using subdirectories
mkdir -p scans/loot/10.10.10.5
echo "admin:P@ssw0rd" > scans/loot/10.10.10.5/ftp_creds.txt

# Or use filename prefix
echo "root:toor" > scans/loot/10.10.10.5_ssh_creds.txt

# Campaign-wide loot (not host-specific)
hashcat -m 1000 hashes.txt rockyou.txt --show > scans/loot/cracked_hashes.txt
```

mAIpper will:
- Parse credentials (`user:pass`) and hashes (NTLM, bcrypt, SHA-256, SAM format)
- Extract file listings (FTP/SMB style)
- Write centralized `Loot/Credentials.md` and `Loot/Hashes.md` with per-host tables
- Add lightweight loot summaries to host notes with links to Loot pages
- Update Priority Targets ranking (hosts with confirmed creds rank highest)

---

# Misc Tool Output

Drop raw text output from any tool into `scans/misc/`:

```bash
# Campaign-wide
cp linpeas_output.txt scans/misc/

# Host-associated (by subdirectory)
mkdir -p scans/misc/10.10.10.5
cp gobuster_results.txt scans/misc/10.10.10.5/
```

mAIpper sends each file to the LLM for interpretation, identifying the tool, extracting findings, and suggesting follow-up commands. Results go to `Scans/<filename> - Misc.md`.

---

# Deep Dive Checkboxes

Host notes include investigation checkboxes next to ports and findings:

```markdown
## Open Ports
- **tcp/445** — SMB microsoft-ds Windows 10 Pro
  - [ ] Investigate: MICROSOFT-DS (tcp/445)
- **tcp/80** — HTTP Apache httpd 2.4.49
  - [ ] Investigate: HTTP (tcp/80)
```

Check a box in Obsidian, run mAIpper again (or press Enter in `-i` mode), and a detailed deep-dive analysis appears as a collapsible callout:

```markdown
  - [x] Investigate: HTTP (tcp/80) ✓ analyzed

## Deep Dives
> [!info]- Deep Dive: HTTP (tcp/80)
> **Attack Surface Analysis:** ...
> **Enumeration Commands:** ...
```

---

# Operator Notes Feedback

Add manual observations to any host note's `## Operator Notes` section:

```markdown
## Operator Notes
Confirmed anonymous FTP access - pulled employee list with 50+ usernames.
SMB null session worked - enumerated domain users and password policy.
```

On the next mAIpper run, these notes are fed into the AI as `[OPERATOR]` context, improving analysis accuracy and attack path suggestions.

---

# Command Line Options

| Option | Description |
|--------|-------------|
| `--init` | Initialize scan directory structure and exit |
| `-i`, `--interactive` | Interactive mode: watch, chat, drop data |
| `--watch-interval SEC` | Seconds between polls in interactive mode (default: 30) |
| `--reanalyze` | Force re-analysis of all files (ignore state) |
| `--scans-dir` | Directory containing scan results (default: `./scans`) |
| `--xml` | Process a single Nmap XML file |
| `--vault` | Obsidian vault output directory (default: `./Obsidian`) |
| `--model` | Ollama model to use |
| `--ollama-url` | URL of Ollama API (default: `http://localhost:11434`) |
| `--no-ollama` | Skip AI analysis |
| `--no-canvas` | Skip canvas generation |
| `--no-nessus` | Skip Nessus processing |
| `--no-burp` | Skip Burp Suite processing |
| `--autorecon DIR` | AutoRecon results directory |
| `--no-autorecon` | Skip AutoRecon processing |
| `--loot DIR` | Loot directory |
| `--no-loot` | Skip loot processing |
| `--misc DIR` | Misc tool output directory |
| `--no-misc` | Skip misc processing |
| `--excel` | Generate Export.xlsx (requires openpyxl) |
| `--temperature` | Ollama sampling temperature (default: 0.15) |
| `--skip-validation` | Skip hallucination checks |
| `--canvas-cols` | Host cards per row in canvas (default: 2) |
| `--canvas-groups-per-row` | Subnet groups per row (default: 3) |
| `-v` | Increase verbosity (INFO) |
| `-vv` | Debug logging |

---

# Example Commands

Process all scans with defaults:

```bash
python mAIpper-v0.10.py
```

Initialize and start interactive mode:

```bash
python mAIpper-v0.10.py --init
python mAIpper-v0.10.py -i
```

Process with explicit directories:

```bash
python mAIpper-v0.10.py --autorecon ~/autorecon_results --loot ~/engagement_loot --misc ~/tool_output
```

Skip AI, just parse and generate notes:

```bash
python mAIpper-v0.10.py --no-ollama
```

Full export with Excel:

```bash
python mAIpper-v0.10.py --excel
```

Use a remote Ollama server:

```bash
python mAIpper-v0.10.py --ollama-url http://10.10.10.5:11434
```

---

# Workflow Example

Typical workflow during an engagement:

1. Initialize and start interactive mode

```bash
python mAIpper-v0.10.py -i
```

2. Run scans (in another terminal)

```bash
nmap -sC -sV -oX scans/nmap/internal.xml 10.10.10.0/24
autorecon 10.10.10.5 -o scans/autorecon
```

3. mAIpper automatically picks up new files and generates vault

4. Open Obsidian and review findings — check investigation boxes for deep dives

5. Add operator notes to host files as you work

6. Collect loot during exploitation

```bash
echo "admin:CompanyPass123" > scans/loot/10.10.10.5/ftp_creds.txt
```

7. Drop misc tool output

```bash
cp linpeas.txt scans/misc/10.10.10.5/
```

8. Press Enter in interactive mode — mAIpper processes changes and deep dives

---

# Hallucination Mitigation

mAIpper uses a four-layer approach to ensure AI accuracy:

1. **Python pre-processing** — structured fact extraction before the LLM sees raw data
2. **Prompt grounding rules** — `[CONFIRMED]`/`[INFERRED]`/`[ASSUMED]` tagging required
3. **Low temperature** — default 0.15 for deterministic output
4. **Post-processing validation** — cross-references CVEs, IPs, ports, and hostnames against source data

---

# Why mAIpper?

Pentesters accumulate large amounts of scan output across many tools. mAIpper helps by:

- Organizing results automatically across Nmap, Nessus, Burp, AutoRecon, loot, and misc tool output
- Suggesting relevant enumeration techniques with ready-to-run commands
- Building a persistent knowledge base with human-in-the-loop AI refinement
- Enabling deep-dive analysis on demand via checkbox-driven investigation
- Visualizing discovered assets in an Obsidian Canvas
- Prioritizing targets based on confirmed vulnerabilities and collected evidence
- Watching for new scan files and auto-processing in the background

---
