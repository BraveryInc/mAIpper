# mAIpper

**mAIpper** is a pentesting workflow tool that ingests scan output, analyzes it with a local LLM via **Ollama**, and generates structured **Obsidian notes and Canvas visualizations**.

The goal is to automatically convert reconnaissance output into **organized operator notes and attack-path suggestions**.

Currently supported:

- **Nmap XML scans**

Planned support:

- NetExec / CrackMapExec
- LDAP enumeration
- SMB enumeration
- Web scanning tools
- Additional recon tooling

---

# Features

- Parse **Nmap XML output**
- Generate **per-host notes** in Obsidian
- Produce **AI-assisted analysis** using Ollama
- Suggest **enumeration tools and attack paths**
- Automatically create an **Obsidian Canvas visualization**
- Organize reconnaissance results into a structured **knowledge base**

---

# Requirements

- Python **3.10+**
- **Ollama**
- An LLM model installed locally

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
├─ mAIpper.py
│
├─ scans/
│   └─ nmap/
│       ├─ internal.xml
│       ├─ external.xml
│       └─ dmz.xml
```

Currently supported:

```
scans/nmap/*.xml
```

You can also specify a different scan directory using:

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
| `--scans-dir` | Directory containing scan results |
| `--xml` | Process a single XML scan file |
| `--vault` | Obsidian vault output directory |
| `--model` | Ollama model to use |
| `--ollama-url` | URL of Ollama API |
| `--no-ollama` | Skip AI analysis |
| `--no-canvas` | Skip canvas generation |
| `-v` | Increase verbosity |
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

