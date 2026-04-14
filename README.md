# mAIpper

**mAIpper** is a pentesting workflow tool that ingests scan output, analyzes it with a local LLM via **Ollama**, and generates structured **Obsidian notes and Canvas visualizations**.

The goal is to automatically convert reconnaissance output into **organized operator notes and attack-path suggestions**.

Currently supported:

- **Nmap XML scans**
- **Nessus XML exports** (`.nessus` files)
- **Burp Suite Pro Scanner XML**

Planned support:

- NetExec / CrackMapExec
- LDAP enumeration
- SMB enumeration
- Additional recon tooling

---

# Features

- Parse **Nmap XML**, **Nessus XML**, and **Burp Suite Pro Scanner XML**
- Generate **per-host notes** in Obsidian, merged across scan sources
- Produce **AI-assisted analysis** using Ollama with hallucination mitigations
- Automatic **Active Directory detection** — domain-specific analysis when AD services are present
- Suggest **enumeration tools and attack paths**
- **Priority Targets** canvas node — AI-ranked list of highest-value hosts across all scan sources
- Automatically create an **Obsidian Canvas visualization**
- Optional **Excel export** (`--excel`) for reporting
- Organize reconnaissance results into a structured **knowledge base**

---

# Requirements

- Python **3.10+**
- **Ollama**
- An LLM model installed locally
- `requests` (required)
- `openpyxl` (optional — only needed for `--excel`)

```bash
pip install requests
pip install openpyxl  # optional
```

Recommended model:

```
qwen2.5:14b-instruct-q5_K_M
```

---

# Install Ollama

Install Ollama:

https://ollama.com

After installation, download the recommended model:

```bash
ollama pull qwen2.5:14b-instruct-q5_K_M
```

Start Ollama:

```bash
ollama start
```

Ollama must be running before mAIpper is executed.

By default mAIpper connects to:

```
http://localhost:11434
```

You can point to a remote Ollama instance using:

```
--ollama-url
```

---

# Scan Directory Layout

Place scan output in a `scans` directory in the working folder.

Example:

```
project/
│
├─ mAIpper-v0.7.py
│
├─ scans/
│   ├─ nmap/
│   │   ├─ internal.xml
│   │   ├─ external.xml
│   │   └─ dmz.xml
│   ├─ nessus/
│   │   └─ internal.nessus
│   └─ burp/
│       └─ webapp.xml
```

Supported scan paths:

```
scans/nmap/*.xml
scans/nessus/*.nessus
scans/burp/*.xml
```

You can also specify a different base scan directory using:

```
--scans-dir
```

---

# Running mAIpper

Basic usage:

```bash
python mAIpper.py
```

This will:

1. Parse Nmap XML scans  
2. Send summarized scan results to Ollama  
3. Generate AI-assisted analysis  
4. Create Obsidian host notes  
5. Generate an Obsidian Canvas visualizing hosts  

---

# Example Output Structure

```
Obsidian/
│
├─ Hosts/
│   ├─ 10.10.10.5.md
│   ├─ dc01.domain.local.md
│   └─ web01.domain.local.md
│
├─ Scans/
│   └─ InternalScan - Nmap.md
│
└─ Assessment Canvas.canvas
```

Host notes include:

- IP address  
- Open ports  
- Service information  
- Link to scan notes  

Scan notes include:

- scan metadata  
- per-host summaries  
- AI analysis  

---

# Command Line Options

| Option | Description |
|------|------|
| `--scans-dir` | Base directory containing scan subfolders (default: `./scans`) |
| `--xml` | Process a single Nmap XML file |
| `--vault` | Obsidian vault output directory (default: `Obsidian`) |
| `--model` | Ollama model to use |
| `--ollama-url` | URL of Ollama API (default: `http://localhost:11434`) |
| `--no-ollama` | Skip AI analysis |
| `--no-canvas` | Skip canvas generation |
| `--no-nessus` | Skip Nessus scan processing |
| `--no-burp` | Skip Burp Suite scan processing |
| `--excel` | Export findings to `Export.xlsx` (requires `openpyxl`) |
| `--canvas-name` | Canvas filename (default: `Assessment Canvas.canvas`) |
| `--canvas-cols` | Host columns per subnet group (default: 2) |
| `--canvas-groups-per-row` | Subnet groups per row (default: 3) |
| `-v` | Verbose logging (INFO) |
| `-vv` | Debug logging |

---

# Example Commands

Process scans using default settings:

```bash
python mAIpper.py
```

Process a specific scan file:

```bash
python mAIpper.py --xml scans/nmap/internal.xml
```

Specify a custom Obsidian vault:

```bash
python mAIpper.py --vault PentestNotes
```

Use a different model:

```bash
python mAIpper.py --model llama3:8b
```

Use a remote Ollama server:

```bash
python mAIpper.py --ollama-url http://10.10.10.5:11434
```

Disable AI analysis:

```bash
python mAIpper.py --no-ollama
```

---

# Example Nmap Command

Generate compatible XML output:

```bash
nmap -sC -sV -oX scans/nmap/internal.xml 10.10.10.0/24
```

---

# Workflow Example

Typical workflow during an engagement:

1. Run scans

```bash
nmap -sC -sV -oX scans/nmap/internal.xml 10.10.10.0/24
```

2. Run mAIpper

```bash
python mAIpper.py
```

3. Open Obsidian

You now have:

- host cards  
- scan analysis  
- enumeration suggestions  
- visual canvas of assets  

---

# Why mAIpper?

Pentesters often accumulate large amounts of scan output across many tools.

mAIpper helps by:

- organizing results automatically  
- suggesting relevant enumeration techniques  
- building a persistent knowledge base  
- visualizing discovered assets  

---

